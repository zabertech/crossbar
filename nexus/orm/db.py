from nexus.orm.common import *
from nexus.orm.collection import *
from nexus.orm.record import *
from nexus.orm.filter import *
from nexus.log import log

import os
import gc

##################################################
# Nexus DB
##################################################
class NexusDB:
    # This is like defining a one-to-many relationships. _collections
    # should hold a dict of name to collection class. So something like
    #
    #   {
    #      'uris': NexusURIs
    #   }
    #
    # This then will cause the creation of NexusCollection object to be
    # available which can be loosely considered something like a table
    #
    _collections = {}

    # This will old a reference from _collection_type to
    # the actual NexusCollections instance
    _cache_collections = {}


    # The root has no UUID
    uuid = '%root'

    def __init__(self, base_path=None):
        if base_path: self.load_config(base_path)

    @property
    def db_(self):
        return self

    def load_data(self):
        uuids_path = self.base_path_ / "uuids"
        self.uuids_path_ = uuids_path
        self.uuids_path_.mkdir(parents=True,exist_ok=True)

        # Setup the sub collections if required
        self._cache_collections = {}
        for attrib, collection_class in self._collections.items():
            collection = collection_class(self)
            object.__setattr__(self, attrib, collection)
            self._cache_collections[attrib] = collection

        # Then we can setup the uri lookup function and search
        # methods for finding files
        self.compute_paths_()

    def load_config(self, base_path):
        """ Now we need to fetch all the information related to users and
            api routes
        """
        self.base_path_ = pathlib.Path(base_path).resolve()
        self.load_data()

    def validate_uid_b64(self, uid_b64):
        """ Ensure that the characters of the uid are within the allowed set
        """
        return bool(re.search(r'^[a-zA-Z0-9_\-\+]{22}$', uid_b64))

    def get(self, uid_b64, record_type=None):
        """ Returns a record based upon the uid_b64 value
        """
        try:
            # We can't search on an empty value
            if not uid_b64:
                return

            if uid_b64 == '%root':
                return self
            resolved_fpath = self.hashed_path(uid_b64).resolve()
            local_fpath = resolved_fpath.relative_to(self.base_path_.resolve())
            record_obj = self.record_from_path(local_fpath)
            if record_type and record_type != record_obj.record_type_:
                raise KeyError(f"Wrong record type for {uid_b64}")
            return record_obj
        except FileNotFoundError:
            return

    def get_collection_(self, collection_attrib):
        """ Returns the NexusCollection instace for the given collection attribu
            raises LookupError if collection_attrib doesn'te exist
        """
        if collection_attrib not in  self._cache_collections:
            collections_str = ", ".join(self._cache_collections.keys())
            raise LookupError(f"{repr(collection_attrib)} not a valid collection. Available Collections {collections_str}")
        return self._cache_collections[collection_attrib]

    def get_collection_type(self, collection_type):
        """ Returns the NexusCollection CLASS for the given collection type
        """
        if collection_type not in COLLECTION_TYPES:
            collections_str = ", ".join(COLLECTION_TYPES.keys())
            raise LookupError(f"{repr(collection_type)} not a valid collection. Available Collections {collections_str}")
        return COLLECTION_TYPES[collection_type]

    ##################################################
    # Indexing
    ##################################################

    def generate(self):
        """ Creates a new, unique UID. This also checks against
            the uid_lookup to ensure there are no collisions
        """
        while True:
            uid = uuid.uuid4().bytes
            # We have to take '==' off since base64 encoding of uuid
            # will leave 2 spare bytes. We don't care about this so
            # we simply trim it off
            uid_b64 = base64.urlsafe_b64encode(uid).decode('utf8')[:-2]

            # We do not accept any hashes that start with '-' since that can
            # confuse the shell lexer. So with a file like
            # /data/db/cookies/-_reFwFmcA5Z4UaaQZZ-OfhxHHRVJ7ge.yaml will
            # make the code think that '_re...' is a switch for a command
            if uid_b64 == '-':
                continue

            # Now verify if the hash already exists in the system. If it
            # doesn't already exist, since we now have a unique, new
            # uuid, break out of the loop and return the value
            hash_path = self.hashed_path( uid_b64 )
            if not hash_path.exists():
                break

        return uid_b64

    def hashed_path(self, uid_b64):
        """ From the base64 encoded UUID, create a hashed path locating
            it on the filesystem
        """
        if not self.validate_uid_b64(uid_b64):
            raise ValueError(f"UID {repr(uid_b64)} invalid.")

        # Convert the base64 encoded uid into a hashed path
        matches = re.findall('(.{2,5})', uid_b64)
        link_path = '/'.join(matches)
        hashed_path = self.uuids_path_ / link_path
        return hashed_path

    def resolve(self, uid_b64):
        """ Returns the path to the appropriate target YAMLEXT file for
            a given uid_b64
        """
        resolved_fpath = self.hashed_path(uid_b64).resolve()
        if not resolved_fpath.exists():
            raise FileNotFoundError(f"Cannot resolve path for {uid_b64}")
        return resolved_fpath

    def unlink(self, uid_b64):
        """ Removes a link going from the uid_b64 hashed path to
            the target pointed to by target_fpath.
        """
        if not uid_b64:
            return

        hashed_path = self.hashed_path(uid_b64)

        if hashed_path.is_symlink():
            hashed_path.unlink()

    def link(self, uid_b64, target_fpath):
        """ Creates a link going from the uid_b64 hashed path to
            the target pointed to by target_fpath. If the targeT_fpath
            already exists, it will overwrite if the target location
            is different
        """
        hashed_path = self.hashed_path(uid_b64)
        target_fpath = pathlib.Path(target_fpath).resolve()

        if hashed_path.is_symlink():

            # If the symlink is pointing to the same place, we ignore
            if hashed_path.resolve() == target_fpath.resolve():
                return

            # We need to remove the previous symlink so we can
            # put in a new one to the new location
            hashed_path.unlink()

        # Need to make the parent path if not already creaetd
        parent_path = hashed_path.parents[0]
        hash_rel_path = pathlib.Path(parent_path).relative_to(self.base_path_)
        parent_path.mkdir(parents=True,exist_ok=True)

        # Strip out the self.target path portion of the
        # target fpath so we can have a relative link
        target_rel_fpath = target_fpath.relative_to(self.base_path_)

        # Then create the symlink if necessary
        relocate_to_base = "../" * len(hash_rel_path.parents)

        hashed_path.symlink_to(
                          pathlib.Path(relocate_to_base)
                              / target_rel_fpath
                      )

        return hashed_path

    def relink_tree(self, node):
        """ This will load up a record and iterate through the object and
            collection to validate that all uid_b64 symlinks are connected
            properly
        """

        # Relink the original node
        node.compute_paths_()
        self.link(node.uuid, node.yaml_fpath_)

        # Update the cache to let them know of the change
        RECORD_CACHE.relocated_uid(node.uuid, node.yaml_fpath_)

        # Go through the collection items
        for collection in node._cache_collections.values():
            collection.compute_paths_()
            for item in collection:
                self.relink_tree(item)

    def compute_paths_(self):
        """ This creates the regexes required to figure out how to get the
            RECORD_OBJ from a path in the local file database. The reason why
            it's so complicated is that we wanted a generic algorithm to extract
            the data. To do this, we had to recursively generate a regex that
            respected the database structure as defined by NexusRecord and
            NexusCollection classes at runtime.
        """

        def _descender(node, index=1):
            """ This function iterates through NexusRecords and NexusCollections
                to build the expected filestructure of the database.
            """
            for attrib, collection_class in node._collections.items():
                record_class = collection_class._record_class

                collection_path = path_format(
                                      collection_class.path_format_,
                                      collection_type = collection_class.collection_type_,
                                  )
                if collection_path[0] == '/':
                    collection_path = collection_path[1:]
                new_record_path = path_format(
                                      record_class.path_format_,
                                      parent_path=re.escape(collection_path),
                                      #key=f"{{{attrib}}}",
                                      key=f"([^/]+)",
                                  )
                new_glob_path = path_format(
                                      record_class.path_format_,
                                      parent_path=re.escape(collection_path),
                                      key=f"*",
                                  )

                # We need to create a closured handler function which is why this nasty structure exists
                def handler_factory(attrib, index):
                    def handler_func(index_node, m):
                        key = name_unescape(m.group(index))
                        node = index_node[attrib][key]
                        return node
                    return handler_func
                handler_func = handler_factory(attrib,index)
                yield attrib, new_record_path, new_glob_path, handler_func

                # We need to create a closured handler function which is why this nasty structure exists
                new_parent_path =  pathlib.Path(new_record_path).parents[0]
                new_parent_glob_path = pathlib.Path(new_glob_path).parents[0]
                for attrib, child_entry, glob_path, child_handler_func in _descender(record_class, index+1):
                    def composite_handler_factory(handler_func, child_handler_func):
                        def composite_handler_func(index_node, m):
                            node = handler_func(index_node, m)
                            return child_handler_func(node, m)
                        return composite_handler_func
                    yield attrib, \
                          f"{new_parent_path}/{child_entry}", \
                          f"{new_parent_glob_path}/{glob_path}", \
                          composite_handler_factory(
                              handler_func,
                              child_handler_func
                          )

        search_globs = {}
        search_tests = []
        for attrib, search_pattern, glob_path, handler_func in _descender(self):

            # Handle the UUID symlink to record lookup handling
            def factory(search_pattern, handler_func):
                match_re = re.compile('^' + search_pattern + '$')
                def fetch_node_handler(path):
                    """ If the path matches the format for a particular NexusRecord
                        type, we will drill down and get the record and return it.
                        If it does not match, we will simply return None
                    """
                    matched_path = match_re.search(path)
                    if not matched_path:
                        return
                    return handler_func(self, matched_path)
                return fetch_node_handler
            search_tests.append(factory(search_pattern, handler_func))

            # Handle the glob patterning for performing searches through the entire
            # database filesystem for scanning and discovery
            search_glob_path = self.base_path_ / glob_path

            # We do str(path)[:1] to strip off the leading /
            search_globs.setdefault(attrib,[]).append(str(search_glob_path)[1:])

        def record_from_path(path):
            """ Go through the different search tests and attempt to
                find the NexusRecord that matches the path
            """
            path_str = str(path)
            for search_test in search_tests:
                node = search_test(path_str)
                if not node: continue
                return node
            return

        object.__setattr__(self, 'record_from_path', record_from_path)
        object.__setattr__(self, 'record_search_globs', search_globs)

    def migrate_uuids(self):
        """ In versions up to 3.0.2022327, UUID hashing was done using 2 character hash
            directories. So they would look like:

            .../data/db/uuids/Ih/zy/-B/ms/Qo/mb/9r/Aa/uk/FK/8A

            This created the issue where it would be up to 11 * num_records
            in the system. When the number of cookies goes beyond
            11 * 30,000 records, the number of inodes starts to collapse.
            We then switched to the 5 character hashes so more like:

            .../data/db/uuids/IBi4H/u59St/S_D_X/Nrv8C/6Q

            Which reduces the inode usage down to 5 * num_records

            This is to allow us to convert any detected 2 character hash
        """

        # Now we can validate that the UUIDs are mapped properly
        for entry in self.uuids_path_.iterdir():

            # Only look at directories that have 2 character entries
            if len(entry.name) != 2:
                continue
            if not entry.is_dir():
                continue

            # Now descend in and try and change the pointer to the new hash format
            for root, dnames, fnames in os.walk(entry, topdown=False):
                root_path = pathlib.Path(root)
                uuid_base = "".join(str(root_path.relative_to(self.uuids_path_)).split('/'))
                for suffix in fnames:
                    uid_b64 = uuid_base + suffix
                    link_fpath = root_path / suffix
                    target_fpath = link_fpath.resolve()
                    hashed_fpath = self.hashed_path(uid_b64)

                    # We only move forward if the target exists
                    if target_fpath.exists():

                        # Create the target link using the new hashed path
                        self.link(uid_b64, target_fpath)
                        log.debug(f"Relinking: {uid_b64}")
                    else:
                        log.warning(f"UUID {uid_b64} to {target_fpath} missing. Non-critical")

                    # Remove the old hashed path
                    link_fpath.unlink()
                    log.debug(f"Removed old link {link_fpath}")

                # If the directory is empty, remove it to free up an inode
                if len(list(root_path.iterdir())) == 0:
                      try:
                          log.debug(f"Removing: {root}")
                          root_path.rmdir()
                      except FileNotFoundError:
                          pass

    def reindex_uuids(self):
        """ Validate that all UUID references to the correct place and
            builds new links if required.
            Since it's possible for someone to copy a set of files (eg.
            a user) and assign it a new username, we'll need to accomodate
            something like that easily.

            We'll do it in two stages:

            1. Iterate through all UUIDs and records and collect:
              a. records where the UUID index points to an invalid path
              b. records that do not have a UUID
              c. records that the UUID points to a different but valid record
              d. UUIDs that point to an invalid path and no record with UUID exists

            Possible oddities

            - Multiple records pointing to same UUID
            - UUID pointed to does not exist
            - Record pointed to does not exist
            - Record has no UUID
            - UUID isn't a symlink
            - Record does not parse as YAMLEXT
            - UUID points to record that has a different UUID
        """

        # Perform any conversions required from older database index formats
        self.migrate_uuids()

        results = {
          'status': 'OK',
          'errors': [],
          'warnings': [],
          'actions': [],
        }

        base_path = self.base_path_.parent.resolve()

        # Fix missing UUID or reassignment
        fix_records_assign_uuid = []

        # Seen UUIDs to map from UUID to record
        # Should be in format
        # {
        #    uuid => [ ts, ts, ts,... ]
        # }
        seen_uuids = {}

        # Mappings of files to UUIDs
        # Should be in the format
        # {
        #    str(pathlib.Path.relative_to(base_path)) => uuid
        # }
        files_to_uuid = {}

        for collection_type, glob_paths in self.record_search_globs.items():
            for glob_path in glob_paths:
                for fpath in pathlib.Path('/').glob(glob_path):

                    # Mangle and poke the file
                    try:
                        target_fpath = fpath.resolve()
                        ts = str(target_fpath.relative_to(base_path))
                    except Exception as ex:
                        results['errors'].append(['BAD_PATH', fpath])
                        log.error(f"{fpath} branch is not in {base_path}! {ex}")
                        continue

                    # Ensure that the file matched is a file
                    if not target_fpath.is_file():
                        log.error(f"{fpath} is not a file")
                        results['errors'].append(['NOT_FILE', ts])
                        continue

                    if not target_fpath.suffix == '.yaml':
                        log.error(f"{fpath} does not end with .yaml")
                        results['errors'].append(['NOT_YAML_EXT', ts])
                        continue

                    # Let's try and parse the data
                    try:
                        with target_fpath.open('r') as f:
                            data = yaml_load(f)
                    except Exception as ex:
                        log.error(f"{target_fpath} did not parse YAMLEXT! {ex}")
                        results['errors'].append(['PARSE_FAIL', ts, str(ex)])
                        continue

                    # Is this a 0 file?
                    if not data:
                        log.error(f"{target_fpath} does not contain any data. Removing.")
                        target_fpath.unlink()
                        continue

                    # If the UUID is missing, that's weird...
                    uuid = data.get('uuid')
                    if not uuid:
                        log.warning(f"{target_fpath} is missing uuid!")
                        fix_record_assign_uuid.append(target_fpath)
                        results['warnings'].append(['NO_UUID',ts])
                        continue

                    # Log the record
                    seen_uuids.setdefault(uuid,[]).append(target_fpath)
                    files_to_uuid[ts] = uuid

        # Iterate through and find the records that have multiple entries
        for uuid, records_fpaths in seen_uuids.items():

            # This holds 
            index_record_fpath = None
            try:
                uuid_fpath = self.hashed_path(uuid)
                index_record_fpath = uuid_fpath.resolve()
            except Exception as ex:
                result['errors'].append([ 'INDEX_PATH_FAIL', uuid, str(ex) ])

            # This is normal so let's just validate that the UUID index
            # points to the right place
            if len(records_fpaths) == 1:

                # If everything matches then we're golden. Move on
                if index_record_fpath == records_fpaths[0] and uuid_fpath.exists():
                    continue

                # If the uuid_fpath doesn't exist but there's one correct target
                # then let's just relink it. The record could just have been
                # manually added to the database and we just need to update the
                # database properly
                elif not uuid_fpath.exists():
                    results['actions'].append([ 'RELINK', uuid, index_record_fpath ])

                # Okay, that's odd, the index is pointing to a different
                # record. That's fine though since we're going to treat this
                # current record as the master. We'll just relink it
                else:
                    results['actions'].append([ 'RELINK', uuid, index_record_fpath ])
                    raise Exception(f"TODO: when uuid {uuid} points to non ts record "\
                                    f"`{index_record_fpath}`. Expected `{records_fpaths[0]}`")

                continue

            # Okay, so the only time we get here is when multiple records points to
            # the same UUID. For this we will assign the UUID to one of the candiates.
            # The winner will be:
            # 1. The record that the UUID index points to will be prioritized
            # 2. If the UUID doesn't point to anyone in particular, use the oldest of 
            #    the records (discovered via ctime reliable as it might be)

            # If the UUID index matches the target. That's great, let's just
            # continue on then since we already have the proper one picked
            if index_record_fpath and index_record_fpath in records_fpaths:
                records_fpaths.remove(index_record_fpath)

            # Okay, so UUID index doesn't exist or doesn't match. Let's find
            # the oldest
            else:
                records_fpaths.sort(key=lambda f:f.stat().st_ctime)
                record_winner = records_fpaths[0]
                self.link(uuid, record_winner.relative_to(base_path))
                records_fpaths.pop(0)
                results['actions'].append([ 'RELINK', uuid, record_winner ])

            # For the remaining, we assign them new UUIDs
            fix_records_assign_uuid.extend(records_fpaths)

        # Now we have a list of records we need to give new UUIDs to
        for record_fpath in fix_records_assign_uuid:
            record_fpath = record_fpath.relative_to(base_path)

            new_uuid = self.generate()
            self.link(new_uuid, record_fpath)

            data = yaml_load_file(record_fpath)
            data['uuid'] = new_uuid
            yaml_dump_file(data, record_fpath)

            record_ts = str(record_fpath)
            files_to_uuid[record_ts] = new_uuid
            seen_uuids.setdefault(new_uuid,[]).append(record_fpath)

            results['actions'].append([ 'NEWUUID', uuid, record_ts ])

        # Now we can validate that the UUIDs are mapped properly
        uuid_root_path = base_path / "db/uuids"
        for root, dnames, fnames in os.walk(self.uuids_path_):

            # If this is an empty directory, let's remove this directory
            entries = len(dnames + fnames)
            if not fnames and not dnames:
                log.info(f"Removing empty directory '{root}'")
                os.rmdir(root)
                continue

            # Skip any directories that do not have "files" since those
            # directories are just a part of the earlier hash path
            if not fnames:
                continue

            uuid_path = pathlib.Path(root)
            uuid_part = uuid_path.relative_to(uuid_root_path)
            uuid_elements = str(uuid_part).split('/')

            # At one point we were using xx/xx/xx/xx/xx/xx/xx based file hashing
            # that uses a whole lot more inodes than xxxxx/xxxxx/xxxxx/xx so we've
            # switched to that. The problem with that is that now we have two
            # different modes that we have to support (for now). We'll accomodate
            # that for awhile with this if statement

            # Try and acquire the base64 UUID from the file path. Each directory element should
            # be a part of the UUID. There's a small chance that the entry found is not
            # a UUID link and just a random file so we do some extra checking here for the
            # number of elements. Otherwise we could just get away with doing a "".join(elements)
            if len(uuid_elements) in [
                                          10, # Old style 2 character hashes create 10 elements
                                          4   # new style 2-5 character hashes create 4 elements
                                      ]:
                uuid_base = "".join(uuid_elements)
            else:
                log.warning(f"Invalid UUID path: {uuid_path}. Expected 4 or 10 elements, got {len(uuid_elements)}")
                continue

            for fname in fnames:
                uuid = uuid_base + fname
                fpath = uuid_path / fname

                # Check that the UUID resolves to 22 characters
                if not len(uuid) == 22: 
                    log.warning(f"UUID:{uuid} index {fpath} does not resolve to 22 characters!")
                    results['errors'].append(['UUID_CHARS', uuid])
                    continue

                # If not a symlink we should warn the user, there
                # should only be symlinks in the uuid index
                if not fpath.is_symlink():
                    log.warning(f"UUID:{uuid} index {fpath} target '{target_fpath}' is not a symlink!")
                    results['errors'].append(['UUID_NOT_SYMLINK', uuid])
                    continue

                # Check if the symlink target exists
                if not fpath.exists():
                    target_fpath = os.readlink(fpath)
                    log.warning(f"UUID:{uuid} index {fpath} symlink target to '{target_fpath}' does not exist! Unlinking.")
                    results['warnings'].append(['UUID_TARGET_NO_EXISTS', uuid])
                    results['actions'].append([ 'REMOVE', uuid, str(fpath.resolve()) ])
                    fpath.unlink()
                    continue

                # Validate that the UUID reference is correct. If it points to the
                # wrong record, remove it since all index references should at this
                # point been corrected by the previous code
                record_fpath = fpath.resolve().relative_to(base_path)
                record_ts = str(record_fpath)
                if record_ts not in files_to_uuid:
                    log.warning(f"UUID:{uuid} index {fpath} symlink target does not exist!")
                    results['warnings'].append(['UUID_TARGET_NO_EXISTS', uuid])
                    results['actions'].append([ 'REMOVE', uuid ])
                    fpath.unlink()
                    continue

                file_uuid = files_to_uuid[record_ts]
                if uuid != file_uuid:
                    log.warning(f"UUID:{uuid} at {fpath} -> {fpath.resolve()} does not point to correct target. Got {file_uuid}! Unlinking")
                    results['warnings'].append(['UUID_WRONG_TARGET', uuid])
                    results['actions'].append([ 'REMOVE', uuid, str(fpath.resolve()) ])
                    fpath.unlink()
                    continue

        return results

    ##################################################
    # Accessors
    ##################################################

    def __getitem__(self, k):
        """ obj[key] indexing and fetching from the data records
        """
        return self.get_item_(k)

    def get_item_(self, k):
        if k in self._collections:
            return getattr(self,k)

        record = self.get(k)
        if record:
            return record

        return LookupError(f"Unknown key or UUID '{k}' request from DB")

    def iter(self, collection_type):
        """ Returns an iterator that goes through all the records of a certain
            type. For that, we need use the globbing object that iterates through
            all the paths associated with a particular collection_type
        """
        if collection_type not in self.record_search_globs:
            raise LookupError(f"Unknown record type {repr(collection_type)}")
        glob_paths = self.record_search_globs[collection_type]
        for glob_path in glob_paths:
            for fpath in pathlib.Path('/').glob(glob_path):
                local_fpath = fpath.resolve().relative_to(self.base_path_.resolve())
                rec = self.record_from_path(local_fpath)
                if not rec: continue
                yield rec

    ##################################################
    # CRUD Operations
    ##################################################

    def query(self,
                  collection_type,
                  conditions=None,
                  sort=None,
                  limit=None,
                  page_index=0
                  ):
        """ Filters collection_type records for anything that maches the conditions

            conditions = nested array structure of conditionals
            order = [
                      [ 'field1', 'asc' ],
                      [ 'field2', 'desc' ],
                    ]
        """
        filter_func = Filter(conditions or [])

        records = []
        for record in self.iter(collection_type):
            if filter_func(record):
                records.append(record)

        # Order the records if required
        for field, order in reversed(sort or []):
            records.sort(key=lambda r:deref(r,field), reverse=order.lower()=='desc')

        # Break the page up into a page if required
        hits = len(records)
        pages = 0
        if limit:
            pages = math.ceil(hits/limit)
            offset = page_index*limit
            records = records[offset:offset+limit]

        return {
            'records': records,
            'page_index': page_index,
            'page': page_index+1,
            'pages': pages,
            'hits': hits,
            'limit': limit,
            'sort': sort,
        }

    def create(self, parent_uid_b64, collection_attrib, data_rec):
        """ Adds a record to the database
        """
        # Locate the parent. If none, we use root
        parent = self.get(parent_uid_b64)
        if not parent:
            raise LookupError(f'Parent {repr(parent_uid_b64)} does not exist')

        # We need to know the collection target
        collection = parent.get_collection_(collection_attrib)

        # Then enter the new record in the database
        return collection.create_(data_rec)

    def update(self, uid_b64s, data_rec):
        """ Updates the record to the keys provided in data_rec
        """
        update_records = []

        # Verify and collect the records to update
        for uid_b64 in uid_b64s:
            record = self.get(uid_b64)
            if not record:
                raise LookupError(f'Record {repr(uid_b64)} does not exist')
            update_records.append(record)

        # Then execute the updates
        for record in update_records:
            record.update_(data_rec).save_()

    def delete(self, uid_b64s):
        """ Remove entries keyed by uid_b64
        """
        for uid_b64 in uid_b64s:
            record = self.get(uid_b64)
            if not record: continue
            record.delete_()

    def stats(self, **kwargs):
        return RECORD_CACHE.stats(**kwargs)

    def bulk_unload(self, nexus_type):
        """ Bulk unloads a single nexus type. EXPERIMENTAL
        """
        for path, nexus_record in list(RECORD_CACHE.items()):
            if nexus_record.record_type_ == nexus_type:
                del RECORD_CACHE[path]
        gc.collect()

