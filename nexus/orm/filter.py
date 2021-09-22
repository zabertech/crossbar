from nexus.orm.common import *

def deref(node,k):
    if '.' in k:
        for kp in k.split('.'):
            if not kp: continue
            node = node[kp]
        return node
    return node[k]

def build_filter_3(f, op, v):
    """ Builds a 3 part filter
    """

    if '=' == op: return lambda r: deref(r,f) == v
    elif '!=' == op: return lambda r: deref(r,f) != v
    elif '>=' == op: return lambda r: deref(r,f) >= v
    elif '>' == op: return lambda r: deref(r,f) > v
    elif '<' == op: return lambda r: deref(r,f) < v
    elif '<=' == op: return lambda r: deref(r,f) <= v
    elif 'in' == op: return lambda r: deref(r,f) in v
    elif 'not in' == op: return lambda r: deref(r,f) not in v
    elif 'ilike' == op: return lambda r: v.lower() in deref(r,f).lower()
    elif 'not ilike' == op: return lambda r: v.lower() not in deref(r,f).lower()
    elif 'like' == op: return lambda r: v in deref(r,f)
    elif 'not like' == op: return lambda r: v not in deref(r,f)
    else: raise ValueError(f"Unknown operator {repr(f)} {repr(op)} {repr(v)} ")


def build_filter_2(operator, conditions):
    """ Builds a 3 part filter
    """
    op = operator.lower()

    func_rack = []
    for c in conditions:
        filter_fn = build_filter(c)
        if filter_fn:
            func_rack.append(filter_fn)

    if 'and' == op:
        if len(func_rack) == 1:
            return func_rack[0]

        def and_op(rec):
            for fn in func_rack:
                if not(fn(rec)):
                    return False
            return True
        return and_op

    elif 'or' == op:
        if len(func_rack) == 1:
            return func_rack[0]

        def or_op(rec):
            for fn in func_rack:
                if fn(rec):
                    return True
            return False
        return or_op

    elif 'not' == op:
        if len(func_rack) == 1:
            fn = func_rack[0]
            return lambda rec: not fn(rec)

        def not_op(rec):
            for fn in func_rack:
                if not(fn(rec)):
                    return True
            return False
        return not_op

    elif 'nor' == op:
        if len(func_rack) == 1:
            fn = func_rack[0]
            return lambda rec: not fn(rec)

        def nor_op(rec):
            for fn in func_rack:
                if fn(rec):
                    return False
            return True
        return nor_op


def build_filter(c):
    # Three part conditions
    if len(c) == 3:
        return build_filter_3(*c)

    # Two parts (AND/OR/NOT/NOT_OR conditions)
    elif len(c) == 2:
        return build_filter_2(*c)

    elif len(c) == 0:
        return

    else:
        raise ValueError(f"Filter definition {repr(c)} cannot be grokked")

class Filter:
    def __init__(self, conditions):
        self.filter_func = build_filter_2('and', conditions)

    def __call__(self, record):
        try:
            return self.filter_func(record)
        except Exception as ex:
            return False
