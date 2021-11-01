from nexus.log import log
from nexus.orm.common import *
from nexus.orm.record import *

##################################################
# Nexus Collection
##################################################
COLLECTION_TYPES = {}

class NexusCollectionMeta(type):
    """ This class is used to collect all the NexusCollection types that are
        declared within an application. This information is subsequently used
        in conjunction with NexusRecord metadata to discover a full file
        heirarchy to reverse lookup records from paths
    """

    def __init__(cls, name, bases, dct):
        # Get the record type and register it
        cls_name = cls.__name__

        # Do not log if the name starts with underscore
        if cls_name[0] == '_':
            return

        collection_type = cls_name.lower()
        if collection_type[:5] == 'nexus':
            collection_type = collection_type[5:]
        cls.collection_type_ = collection_type

        # The first entry will have this empty
        if cls_name != 'NexusCollection':
            cls.not_root_init()

        COLLECTION_TYPES[collection_type] = cls

    def not_root_init(cls):
        collection_type = cls.collection_type_

        # We are going to assume that the NexusRecord
        # for this collection already has been declared
        # If the singleton class has not been defined,
        # let's resolve it for the user. By convention
        # we'll assume that we're using plurals and that
        # the collections have an "s" at the end
        if not cls._record_class:
            if collection_type[-1] != 's':
                raise ValueError(f"Collection {collection_type} does not end with 's'. Need _record_class defined.")
            record_type = collection_type[:-1]
            if record_type not in RECORD_TYPES:
                raise ValueError(f"No record type {record_type} for collection {collection_type}")
            try:
                cls._record_class = RECORD_TYPES[record_type]
            except KeyError:
                raise ValueError(f"Couldn't find record type {record_type} for collection {collection_type}")

        # Pull the keyname locally as well
        cls._key_name = cls._record_class._key_name


class NexusCollection(metaclass=NexusCollectionMeta):

    # This lays out how the path should be resolved bidirectionally
    # these are not proper format strings, they are pseudo strings that
    # do not accept functions between the {} (this makes it possible
    # to do regex patterns as well as cheat with format() for populating
    # them).
    path_format_ = '{parent_path}/{collection_type}'


    # This is used when the record is shown to the user via
    # a print. Generally not that useful outside of debugging. The
    # current instance is available as {r} in the format string
    _str_format = '[{r.collection_type_}:{r.collection_path_}]'

    # This is the NexusRecord class that this collection manages
    _record_class = None

    # Computed from _record_class, the key that the NexusRecord uses
    # to uniqely identify individual entries
    _key_name = None

    # Computed at creation, this is the name of the record collection based upon
    # the classname. If the name of the class starts with Nexus, it will
    # then strip off the prefix, lowercase the rest and use that as the
    # identifer for the collection type
    collection_type_ = None

    # The current path holding the record. Used for the sub collections
    # if there are any. This is computed by the initialization code
    base_path_ = None

    # Cached values for file based ops
    glob_pattern_ = None
    key_regex_ = None

    @classmethod
    def path_resolve_(cls, parent):
        # Find out the reference to the top level DB
        parent_path = parent.base_path_
        resolved_path = cls.path_format_.format(
                            parent_path = parent_path,
                            collection_type = cls.collection_type_,
                        )
        return pathlib.Path(resolved_path)

    def __new__(cls, parent):
        """ Ensures that the instance is a singleton keyed by
            the collection_path
        """

        obj = super().__new__(cls)

        # The parent data record that instantiated this
        obj.parent_ = parent

        # We want to maintain a direct reference to the top level NexusDB
        obj.db_ = parent.db_

        # Setup the collection path if required and cache the path in the object
        obj.compute_paths_()

        # Call the record specific implementation code
        obj.init_()

        return obj

    def compute_paths_(self):
        """ Figures out what the path to the NexusRecord etc should be
        """
        collection_path = self.path_resolve_(self.parent_) 
        collection_path.mkdir(parents=True,exist_ok=True)

        # Setup the collection path if required and cache the path in the object
        self.collection_path_ = collection_path

        # Set the object's base (parent) path
        self.base_path_ = collection_path

        # Generate the globbing patterns used for searching records in the iterator
        parent_path = str(self.base_path_)
        if parent_path[0] == '/':
            parent_path = parent_path[1:]
        self.glob_pattern_ = path_format(
                                    self._record_class.path_format_,
                                    key='*',
                                    parent_path=parent_path
                                )

        # Then generate the regex pattern that can be used to extract the key from
        # the file path (usually generated from a glob pattern)
        self.regex_pattern_ = '^' + path_format(
                                        self._record_class.path_format_,
                                        key='(?P<key>([^/]+))',
                                        parent_path=re.escape(str(self.base_path_))
                                    ) + '$'

    def init_(self):
        """ Subclassing this can be used to implement record specific initialization
        """
        pass

    def get_(self, key=None, default=None, uuid=None):
        """ Fetches a record based upon the key or base64 UUID.
        """
        if uuid:
            resolved_fpath = self.db_.resolve(uuid)
            if not resolved_fpath:
                return default

            # There's a chance that we have provided a uuid that exists but points
            # to record that is not the same type as well
            key_match = re.search(self.regex_pattern_, str(resolved_fpath))
            if not key_match:
                return default

            # Welp, it seems like it may have worked, so let's just load up the
            # record
            key = key_match.group('key')

        if not key:
            raise KeyError("Require key or uuid to be defined")

        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def __bool__(self):
        for item in self:
            return True
        return False

    def __contains__(self, key):
        return self._record_class.exists_(key, self)

    def __getitem__(self, key):
        if not self.exists_(key):
            import traceback
            log.warn("\n".join(traceback.format_stack()))
            raise KeyError(f"'{key}' is not a valid {self.__class__.__name__} key")
        return self.instantiate_({
            self._key_name: key
        })

    def __iter__(self):
        """ Allows conversion to list
        """
        for key, key_obj in self.items_():
            yield key_obj

    def items_(self):
        """ Allows iteration over the keys
        """
        for key_fpath in pathlib.Path('/').glob(self.glob_pattern_):
            key_match = re.search(self.regex_pattern_, str(key_fpath))
            if not key_match:
                continue

            key_unescaped = key_match.group('key')
            key = name_unescape(key_unescaped)

            # This is a sanity check. It should be possible to escape the
            # key into a path that matches the filesystem. There's a chance
            # that the file could have simply been copied with a rename which
            # might then mean that the file contains chars that would normally
            # be escaped. 
            if name_escape(key) != key_unescaped:
                log.error(f"Skipping {key_fpath} for `{key}` as it appears to not be escaped. Fix and reindex the database!")
                continue

            key_obj = self[key]

            # (weird if we do) If we get a None object, we simply ignore it
            # and move to the next.
            if key_obj is None:
                continue

            yield (key, key_obj)

    def list_(self, yaml=False):
        """ Returns a json-able list of records
        """
        collection_list = []
        for item in self:
            collection_list.append(item.dict_(yaml))
        return collection_list

    def create_(self, data_rec):
        return self.instantiate_( data_rec )

    def instantiate_(self, data_rec):
        return self._record_class(data_rec, self)

    def exists_(self, key):
        return self._record_class.exists_(key, self)

    def __str__(self):
        return self._str_format.format(r=self)

