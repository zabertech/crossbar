from nexus.orm.common import *

##################################################
# Nexus Metaclass for Record Types
##################################################
RECORD_TYPES = {}


class NexusRecordMeta(type):
    """ This class is used to collect all the NexusRecord types that are
        declared within an application. This information is subsequently used
        in conjunction with NexusCollection metadata to discover a full file
        heirarchy to reverse lookup records from paths
    """
    def __init__(cls, name, bases, dct):
        # Get the record type and register it
        cls_name = cls.__name__
        record_type = cls_name.lower()

        # Do not log if the name starts with underscore
        if record_type[0] == '_':
            return

        # Okay, let's find out information about this class
        if record_type[:5] == 'nexus':
            record_type = record_type[5:]
        cls.record_type_ = record_type

        RECORD_TYPES[record_type] = cls

##################################################
# Nexus Record
##################################################

class NexusRecord(metaclass=NexusRecordMeta):

    # Reference to the top-level NexusDB object. This handles things like
    # UUID allocation, lookup, marshalling, etc
    db_ = None

    # This is where the primary cache of raw data for the record itself is
    # kept. Note that any sub collection data is not held here. As the data
    # is loaded from a yamlfile, this should be a ruamel.yaml CommentedMap
    # instance
    data_rec_ = None

    # A link to the parent record that owns this one. Say the role that
    # owns URIs
    parent_ = None

    # When true, and almost always will be, this will throw a KeyError
    # when a column that doesn't exist is requested or attempted to be set
    strict_keys_ = True

    # The current path holding the record. Used for the sub collections
    # if there are any. This is computed by the initialization code
    base_path_ = None

    # Record state. Which can beone of:
    # RECORD_STATE_REMOVED = 0
    # RECORD_STATE_DEFAULT = 1
    state_ = RECORD_STATE_DEFAULT

    # This is like defining a one-to-many relationships. _collections
    # should hold a dict of name to collection class. So something like
    #
    #   {
    #      'uris': NexusURIs
    #   }
    #
    # This then will cause the creation of 
    #
    _collections = {}

    # This will old a reference from _collection_type to
    # the actual NexusCollections instance
    _cache_collections = {}

    # This is used when the record is shown to the user via
    # a print. Generally not that useful outside of debugging. The
    # current instance is available as {r} in the format string
    _str_format = '[{r.record_type_}:{r.yaml_fpath_} uid_b64:{r.uuid}]'

    # When using dict_, the fields will be omitted from returned noted
    # in here will be omitted from the results
    _exclude_keys_dict = ['version']

    # What is the column name of primary key of this set of records?
    _key_name = 'key'

    # What is the value of the primary key in this record? (Cached)
    _key_value = None

    # This is for the exceptional case when we're changing the key value
    # this is normally set to None and it's rarely touched
    _key_value_new = None

    # Computed at creation, this is the name of the record type based upon
    # the classname. If the name of the class starts with Nexus, it will
    # then strip off the prefix, lowercase the rest and use that as the
    # identifer for the record type
    record_type_  = None

    # This lays out how the path should be resolved bidirectionally
    # these are not proper format strings, they are pseudo strings that
    # do not accept functions between the {} (this makes it possible
    # to do regex patterns as well as cheat with format() for populating
    # them).
    path_format_ = '{parent_path}/{key}.yaml'

    # This also defines what part of the path the record owns. This is
    # relevant when the system needs to determine what files and folders
    # move when a record is removed or a key is deleted
    ownership_path_format_ = '{parent_path}/{key}.yaml'

    # The template to what the yaml data should
    # look like if we're creating it from scratch
    _yaml_template = YAML_TEMPLATE_DEFAULT

    # Path to where the data source file for this record is found
    yaml_fpath_ = None

    # This is computed by the init. This is used to determine if data
    # has been modified outside of the system. If so, it will notice that
    # the mtime is changed and will trigger a reload of the data at the next
    # collection.get_ of the object
    yaml_fpath_mtime = None

    # Constraints are things that prevent bad values from showing up in
    # the code. This should be setup in the format
    # {
    #    fieldname: lambda value, key, record: True/False
    # }
    _constraints = {}

    @classmethod
    def path_resolve_(cls, key, parent):
        # Find out the reference to the top level DB
        resolved_path = cls.path_format_.format(
                            parent_path = parent.base_path_,
                            key = key,
                        )
        return pathlib.Path(resolved_path)

    @classmethod
    def ownership_path_resolve_(cls, key, parent):
        # This returns the file or domain that the record owns
        # this is used for deletes and key renames
        resolved_path = cls.ownership_path_format_.format(
                            parent_path = parent.base_path_,
                            key = key,
                        )
        return pathlib.Path(resolved_path)

    @classmethod
    def exists_(cls, key, parent):
        yaml_fpath = cls.path_resolve_(key, parent) 
        return yaml_fpath.exists()

    def __new__(cls, data_rec, parent):
        """ Ensures that the instance is a singleton keyed by
            the yaml_fpath
        """
        # Discover the key
        key = data_rec[cls._key_name]
        del data_rec[cls._key_name]

        if not key:
            raise ValueError(f"{cls._key_name} may not be empty or null")

        yaml_fpath = cls.path_resolve_(key, parent) 

        # If we have a copy of the single cached, let's use that
        if yaml_fpath in RECORD_CACHE:
            return RECORD_CACHE[yaml_fpath]

        obj = super().__new__(cls)

        # Setup the parent. As all NexusRecords are collected under a
        # NexusCollection, we know that it should be a partne reference
        obj.parent_ = parent

        # Find out the reference to the top level DB
        obj.db_ = parent.db_

        # Cache the key value
        obj._key_value = key

        # If we need to move to a new key value
        obj._key_value_new = None

        # Setup paths for finding the record on the system
        obj.compute_paths_()

        # Do the initial load if required
        obj.load_()

        # We mark this as True if for some reason a part of the
        # init requires us to save the data to disk
        requires_save = False

        # If a data_rec is provided, we're going to
        # assume it's values that should override the
        # defaults or the currently loaded yaml values
        if data_rec:
            obj.update_(data_rec)
            requires_save = True

        # If we don't have a UUID let's fix that
        if not obj.uuid:
            obj.uuid = obj.db_.generate()
            requires_save = True

        # Setup the sub collections if required
        obj._cache_collections = {}
        for attrib, collection_class in obj._collections.items():
            collection = collection_class(obj)
            obj._cache_collections[attrib] = collection

        # Normalize if we want to do anything special
        obj.init_()

        # If there's been any action that makes the data dirty
        # let's save it
        if requires_save:
            obj.save_()

        # Rack the object and go
        RECORD_CACHE[yaml_fpath] = obj
        return obj

    def __init__(self, *args, **kwargs):
        """ Called everytime a NexusRecord is 'instantiated'
        """
        self.reload_()

    def load_(self):
        """ Loads the yaml path. There are two side effects to the
            object.
            1. Loads the data if available into self.data_rec_
            2. Caches the mtime of the file at load so we can detect
                when changes may have happened
        """
        # Attempt to load from the YAML file first
        # if it isn't available, load the default
        # configuration then preload all values
        defaults = self.defaults_()
        try:
            self.data_rec_ = yaml_load(self.yaml_fpath_.open('r'))
            for k,v in defaults.items():
                self.data_rec_.setdefault(k,v)
            self.yaml_fpath_mtime = self.yaml_fpath_.stat().st_mtime
        except FileNotFoundError as ex:
            self.data_rec_ = yaml_load(self._yaml_template)
            self.data_rec_.update(defaults)
        return True

    def compute_paths_(self):
        """ Figures out what the path to the NexusRecord etc should be
        """

        yaml_fpath = self.path_resolve_(self._key_value, self.parent_)

        # Setup associations
        self.yaml_fpath_ = yaml_fpath

        # Set the object's base (parent) path
        self.base_path_ = yaml_fpath.parents[0]

    def reload_(self, force=False):
        """ If there's been a change the source yaml file, reload
            the data. We can force the data to be loaded anyways
            by setting the force parameter to True

            You can generally ignore the results but this will return
            a true value if the system refreshes the data
        """
        if not force:
            yaml_fpath_mtime = self.yaml_fpath_.stat().st_mtime
            if self.yaml_fpath_mtime == yaml_fpath_mtime:
                return False
        return self.load_()

    def yaml_(self):
        """ Returns the YAML representation of the data
        """
        return yaml_dumps(self.data_rec_)

    def save_(self):
        """ Stores the yaml data into the target path
        """

        # Handle the weird case when we change key values
        if self._key_value_new:
            target_ownership_path = self.ownership_path_resolve_(
                                          self._key_value_new,
                                          self.parent_
                                        )

            # Verify that the target path doesn't already exist
            if target_ownership_path.exists():
                raise ValueError(f"{self._record_type}.{self._key_name} = {self._key_value_new} already exists!")

            # Let's relocate all the data
            source_ownership_path = self.ownership_path_resolve_(
                                            self._key_value,
                                            self.parent_
                                          )
            source_ownership_path.rename(target_ownership_path)

            # Update the local to the new key value
            self._key_value = self._key_value_new
            self._key_value_new = None

            # Reload the collections and ask them to rebuild the uid
            # symlink database
            self.db_.relink_tree(self)

        # Make sure we have the parent paths
        parent_path = self.yaml_fpath_.parents[0]
        if not parent_path.exists():
            parent_path.mkdir(parents=True,exist_ok=True)

        yaml_dump_file(self.data_rec_, self.yaml_fpath_)
        self.db_.link(self.uuid, self.yaml_fpath_)
        self.yaml_fpath_mtime = self.mtime_()

        return self

    def delete_(self):
        """ Removes this record
        """
        try:
            ownership_path = self.ownership_path_resolve_(
                                    self._key_value,
                                    self.parent_,
                              )

            # Need to iterate over the collections we manage
            # and remove them from the RECORD_CACHE as well
            # FIXME: At some point we can make this way faster by
            # simply collecting UUIDs then whacking the subdirs
            for collection in self._cache_collections.values():
                for item in collection:
                    item.delete_()

            # Remove the owned part of the path
            if ownership_path.is_dir():
                shutil.rmtree(ownership_path)
            else:
                ownership_path.unlink()

        # Already removed. Don't worry about it.
        except FileNotFoundError:
            pass

        # Remove the internal cache references and the UUID reference as well
        finally:
            RECORD_CACHE.pop(self.yaml_fpath_)

            # Also need to remove the UUID reference
            self.db_.unlink(self.uuid)

        self.state_ = RECORD_STATE_REMOVED

        return self

    def touch_(self):
        """ Updates the current yaml_fpath's mtime state to the value
            to the current timestamp
        """
        if self.mtime_() == self.yaml_fpath_mtime:
            self.yaml_fpath_.touch()
            self.yaml_fpath_mtime = self.mtime_()
        else:
            self.yaml_fpath_.touch()

    def mtime_(self):
        """ Returns the file's last modification timestamp
        """
        return self.yaml_fpath_.stat().st_mtime

    def defaults_(self):
        """ Returns the default data for the record
        """
        return {}

    def init_(self):
        """ Ensure all permissions are in properly instantiated. This is used by the
            subclassing module to do anything special for that particular record type.
            By default we do nothing.
        """
        pass

    def dict_(self, yaml=False):
        """ Get a JSON suitable dict representation of the API Key record
        """

        # Convert the commented map into a dict
        data = dict(self.data_rec_)

        # Remove some keys we don't want exported
        for exclude_key in self._exclude_keys_dict:
            if exclude_key not in data:
                continue
            del data[exclude_key]

        for k, v in data.items():
            data[k] = simplify(v)

        # Include the key
        data[self._key_name] = simplify(self[self._key_name])

        # Include the parent UUID
        data['owner'] = self.owner

        return data

    def get_(self, k, default=None):
        """ Gets an item from the data_rec
        """
        try:
            return self.get_item_(k)
        except KeyError:
            return default

    def get_collection_(self, collection_attrib):
        """ Returns the NexusCollection instace for the given collection type
            raises LookupError if collection_attrib doesn'te exist
        """
        if collection_attrib not in  self._cache_collections:
            collections_str = ", ".join(self._cache_collections.keys())
            raise LookupError(f"{repr(collection_attrib)} not a valid collection. Available Collections {collections_str}")
        return self._cache_collections[collection_attrib]


    def set_(self, k, v):
        """ Sets an item from the data_rec
        """
        return self.set_item_(k, v)

    def update_(self, data_rec):
        """ Do an update from a dict into the record
        """
        for k,v in data_rec.items():
            self[k] = v
        return self

    def __getattr__(self, k):
        """ Fetch data from data_rec via obj.attribute
        """
        try:
            return self[k]
        except KeyError:
            return object.__getattribute__(self, k)

    def __setattr__(self, k, v):
        """ Set a value in data_rec[k] via obj.k = value
        """
        try:
            object.__getattribute__(self, k)
            object.__setattr__(self, k, v)
        except AttributeError as ex:
            self.set_item_(k,v)

    def __getitem__(self, k):
        """ obj[key] indexing and fetching from the data records
        """
        return self.get_item_(k)

    def get_item_(self, k):
        """ Gets an item from the local cache.
        """

        if k == self._key_name:
            try:
                return self._key_value
            except AttributeError as ex:
                return self.yaml_fpath_.stem
        elif k in self._cache_collections:
            return self._cache_collections[k]

        # We also want to return the parent UUID if it's available
        elif k == 'owner':
            # As all NexusRecords are collected under a NexusCollection,
            # we know that it should be a partne reference
            return self.parent_.parent_.uuid

        # We also want to return the parent UUID if it's available
        elif k == 'owner_':
            # As all NexusRecords are collected under a NexusCollection,
            # we know that it should be a parent reference
            return self.parent_.parent_

        else:
            return self.data_rec_[k]

    def __setitem__(self,k,v):
        """ Set a value in data_rec[k] via obj[k] = value
        """
        self.set_item_(k, v)

    def set_item_(self, k, v):
        if self.state_ == RECORD_STATE_REMOVED:
            raise LookupError(f"Record has been removed!")

        if k in self._collections:
            raise KeyError(f"May not set a value to collection name {k}")

        elif k == self._key_name:
            if not v:
                raise ValueError(f"Key {self._key_name} may not be empty")
            self._key_value_new = v

        # We currently don't allow reparenting of records
        # TODO, FIXME: Maybe we can implement this in the future
        elif k == 'owner':
            if v != self._parent._parent.uuid:
                raise ValueError(f"Relocation of parent currently not permitted")

        elif self.strict_keys_ and k not in self.data_rec_:
            available_keys = ", ".join(self.data_rec_.keys())
            raise KeyError(f"Key '{k}' not a valid key of '{self}'. Available keys: {available_keys}")

        elif k in self._constraints:
            if not self._constraints[k](v, k, self):
                raise ValueError(f"Value {repr(v)} invalid for '{k}'")
            self.data_rec_[k] = v

        else:
            self.data_rec_[k] = v

    def __repr__(self):
        return "{}({})".format(
                          self.__class__.__name__,
                          self.data_rec_
                        )

    def __str__(self):
        return self._str_format.format(r=self)

    def __repr__(self):
        return self._str_format.format(r=self)

