import re
import collections

class IntConstant(int):
    def __new__(cls, value):
        self = int.__new__(cls, value)
        return self

PTN_EXACT = IntConstant(0)
PTN_REGEX = IntConstant(1)
PTN_PREFIX = IntConstant(2)

class URIElement(str):
    """ This is just one element of a URI. Every URI will be
        composed of one or more of these nodes in a sequential
        list

        This is just a string with a couple additional useful properties
    """
    def __new__(cls, pattern, pattern_type=PTN_EXACT, last=False, pattern_path=None):
        self = str.__new__(cls, pattern)
        self.pattern_type = pattern_type
        self.last = last
        self.pattern_path = pattern_path
        return self

    def __repr__(self):
        if self == PTN_EXACT:
            return f'EXACT({self})'
        elif self == PTN_REGEX:
            return f'REGEX({self})'
        elif self == PTN_PREFIX:
            return f'PREFIX'
        else:
            return f'UNKNOWN({self})'

    def __eq__(self, other):
        """ If `other` is an integer type it's probably a comparison
            to see if the the element is a certain type
        """
        if isinstance(other, IntConstant):
            return self.pattern_type == other
        else:
            return super().__eq__(other)

    def __ne__(self, other):
        """ If `other` is an integer type it's probably a comparison
            to see if the the element is NOT a certain type
        """
        if isinstance(other, IntConstant):
            return self.pattern_type != other
        else:
            return super().__ne__(other)

    def __getattr__(self,k):
        if k == 'is_regex':
            return self and self.pattern_type == PTN_EXACT

def uri_split(uri):
    return uri.split('.')

def uri_pattern_split(uri):
    """ Returns an array of URI elements.

        We expect two types of URI elements.

        1. basic URI elements that are like [^\.]+
        2. pattern based elements thare /SOMETHING/

        The problem is that in some cases, we may have a URi that
        looks like this:

            part1.part2./pattern.here/.part4

        If we simply split on '.', we screw up the portion that is
        '/pattern.here/'. So how to we pick the sections to break?

        There are other cases such as this where the pattern
        is completely broken:

            part1.part2./broken.pattern/here.part4

        So this function will do its best to split on
        normal and patterns and when it discovers something weird
        throw a ValueError explaining why it can't.

        Errors thrown:

        - Element is blank: part1..part2
        - Bad regex: part1./foo/bar.part2

    """
    elements = []
    past_elements = []
    while uri:

        # If the URI element is a regular expression, see if
        # we can extract it out
        if uri[0] == '/':
            m = re.search('^(/((?:\\\/|[^\/])*?)/)(.*)',uri)
            ( raw_element, element, uri ) = m.groups()
            past_elements.append(raw_element)
            element_type = PTN_REGEX

            if uri:
                if uri[0] != '.':
                    raise ValueError('Looks like a broken pattern in URI!')
                else:
                    uri = uri[1:]

        elif uri == '*':
            element = uri
            past_elements.append(element)
            element_type = PTN_PREFIX
            uri = ''

        # If the URI element not a regular expression we just
        # need to split on the next '.'
        else:
            try:
                ( element, uri ) = uri.split('.',1)
                past_elements.append(element)
                element_type = PTN_EXACT

            # When there are no patterns left
            except ValueError:
                element = uri
                element_type = PTN_EXACT
                uri = ''

        last = not uri
        elements.append(URIElement(element, element_type, last, ".".join(past_elements)))
    return elements


class NexusAuthNoPermissions(Exception):
    pass

class TrieNodeCollection(collections.UserDict):
    def __contains__(self, item):
        if isinstance(item, URIElement):
            return super().__contains__(str(item))
        else:
            return super().__contains__(item)

    def __setitem__(self, k, v):
        if isinstance(k, URIElement):
            return super().__setitem__(str(k),v)
        else:
            return super().__setitem__(k,v)

    def __getitem__(self, k):
        if isinstance(k, URIElement):
            return super().__getitem__(str(k))
        else:
            return super().__getitem__(k)


class TrieNode:
    pattern_path = None

    match_exact = None
    match_pattern = None
    match_prefix = None
    match_data = None
    data = None
    rules = None

    def __init__(self, pattern_path=None):
        self.pattern_path = pattern_path
        self.match_exact = TrieNodeCollection()
        self.match_pattern = TrieNodeCollection()
        self.match_data = {}
        self.rules = []

    def append(self, match, data):
        self.rules.append([match, data])

        elements = uri_pattern_split(match)

        index = self
        element_count = len(elements)
        element_exact = 0
        for element in elements:
            # Handle the element differently depending on the type
            if element is None or element == '':
                raise Exception(f"No empty elements allowed in '{match}'")
            elif element == PTN_EXACT:
                search_list = index.match_exact
                element_exact += 1
            elif element == PTN_REGEX:
                search_list = index.match_pattern
            elif element == PTN_PREFIX:
                if not element.last:
                    raise Exception(f"'*' must be the last element of '{match}'")
                if index.match_prefix:
                    raise Exception(f"Pattern {match} conflicts with another rule with the same pattern")
                index.match_prefix = TrieNode(pattern_path=element.pattern_path)
                index = index.match_prefix
                element_count -= 1 # we don't consider the '*' at the end of a prefix to be an element
                break
            else:
                raise Exception(f"Do not know how to handle '{element}' in '{match}'")

            if element not in search_list:
                search_list[element] = TrieNode(pattern_path=element.pattern_path)
            index = search_list[element]

        # Set the node's handler. All leaves of this data
        # tree must be associated with a data record (otherwise
        # we don't know what to do with the information)
        if index.data:
            raise Exception('Metadata already declared. Collision!')
        index.data = data
        index.match_data = {
                                'element_count': element_count,
                                'element_exact': element_exact
                              }

        return self

    def _match(self, elements):
        """
        """
        # The final list of matched resolved below this node
        resolved_nodes = []

        # The nodes that have matched up to this point (not the final set)
        matched_nodes = []

        # Pop the first element off
        elements = list(elements) # since we clobber
        element = elements and elements.pop(0)

        # If there a prefix match on this?

        if element:
            # Check for exact
            if element in self.match_exact:
                matched_node = self.match_exact[element]
                matched_nodes.append(matched_node)

            # Then check for regex matches as well
            for pattern, node in self.match_pattern.items():
                if re.search(pattern, element, re.IGNORECASE):
                    matched_nodes.append(node)
        elif self.data:
            resolved_nodes.append(self)

        # And drill further down as required
        for node in matched_nodes:
            resolved_nodes += node._match(elements) or []

        if element and not resolved_nodes and self.match_prefix:
            resolved_nodes.append(self.match_prefix)

        return resolved_nodes

    def match(self, uri):
        """
        """

        elements = uri_split(uri)
        matches = self._match(elements)

        if not matches: return

        # If there are multiple matches, try and break the tie
        if len(matches) > 1:
            matches.sort(key=lambda a: (a.match_data['element_count'],a.match_data['element_exact']), reverse=True)
            a = matches[0].match_data
            b = matches[1].match_data
            if a['element_count'] == b['element_count'] \
              and a['element_exact'] == b['element_exact']:
                  raise Exception(f"Conflict in match resolution! {matches[0].pattern_path} "\
                                  f"vs {matches[1].pattern_path} for URI '{uri}'")

        return matches[0]

    def dumps(self,depth=0):
        """ Create a textual representation of the current data
            Trie
        """
        s = ''
        if not depth:
            s = f'root: {self.data}\n'
        indent = '  ' * (depth + 1)
        if self.match_prefix:
            s += f'{indent}{self.match_prefix.pattern_path} {self.match_prefix.data} {self.match_prefix.match_data}\n'
        for element, node in self.match_exact.items():
            s += f'{indent}{node.pattern_path} {node.data} {node.match_data}\n'
            s += node.dumps(depth+1)
        for element, node in self.match_pattern.items():
            s += f'{indent}{node.pattern_path} pattern {node.data} {node.match_data}\n'
            s += node.dumps(depth+1)
        return s



