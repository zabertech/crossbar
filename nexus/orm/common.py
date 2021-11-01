import io
import re
import math
import time
import base64
import datetime
import secrets
import pathlib
import passlib.hash
import ruamel.yaml
import shutil
import uuid

YAML_TEMPLATE_DEFAULT = """
# Database version. This key should always be present
version: 1

# Database Universal Unique Record ID
uuid: null

"""

RECORD_STATE_REMOVED = 0
RECORD_STATE_DEFAULT = 1

# Identifies which characters will be escaped when writing the name
# or key to the filesystem
CONVERT_CHARS =  r'([#%&{}\<>*?/ $!\'":@+`|=^\n])'

#####################################################
# Path Regex Handlers
#####################################################

def name_escape(s):
    """ Escapes the string into something that's somewhat human
        readable so that it can be saved onto the filesystem
    """
    res = re.sub(
              CONVERT_CHARS,
              lambda a: f"^{hex(ord(a.group(1)))[2:]}",
              s
            )
    return res

def name_unescape(s):
    """ Unescapes escaped string into the original string
    """
    res = re.sub(
              r'\^(..)',
              lambda a: f"{chr(int(a.group(1), base=16))}",
              s
            )
    return res

def path_format(path_format, **tags):
    def repl(m):
        k = m.group('tag')
        return tags.get(k,'')
    return re.sub( '{(?P<tag>[^}]+)}', repl, path_format )

class DictObject(dict):
    def __init__(self, noerror=False, *args, **kwargs):
        super(DictObject, self).__init__(*args, **kwargs)
        self.__dict__ = self
        self.noerror_ = noerror

    def __getattr__(self,k):
        if self.noerror_:
            return self.__dict__.get(k)
        raise Exception("No attribute {}".format(k))

    def __nonzero__(self):
        # Evaluate the object to "True" only if there is data contained within
        return bool(self.__dict__.keys())

##################################################
# RecordCache Cache
# This dict should hold a reference keyed by the filepath
# to the record, so:
# {
#     yaml_fpath => object instance
# }
##################################################

PATH_COUNTER = 0
class PathRecord:
    def __init__(self, path_str):
        global PATH_COUNTER

        # Paths
        self.p = path_str

        # IDs
        PATH_COUNTER += 1
        self.i = PATH_COUNTER

        # UUID
        self.u = None

        # References
        self.r = []

    @property
    def path(self): return self.p

    @property
    def id(self): return self.i

    @property
    def uid_b64(self): return self.u

    @uid_b64.setter
    def uid_b64(self, v): self.u = v

    def __str__(self):
        return f"[{self.path} @{self.uid_b64}]"

    def __repr__(self):
        return f"[{self.path} @{self.uid_b64}]"

class RecordCache(dict):
    """ This is used to ensure we maintain a singleton-ness for
        individual NexusRecord entries. Without it we could have multiple
        NexusRecord references for the same entry in the app and the changes
        could potentially clobber each other. This way we can ensure that
        by trapping NexusRecord.__new__, we can return the singleton for
        the record as needed.

        We need to do several types of lookups. The most common is
        simply to find out the record associated with a particular path.

        1. path -> NexusRecord Instance

        The next is when the user updates a NexusRecord's key. In that
        case the path is invalidated and we need to update the NexusRecord's
        path in the system as well as all of its child records.

        In that case we have the uid_b64 and the new path location. So we need
        to go through and:

        1. Locate the current associated PathRecord from the UUID
        2. Create a new PathRecord for the new Path
        3. Amend the pointer to the NexusRecord from the old PathRecord to
            the new PathRecord
        4. Drop the old PathRecord

    """

    # This allows mapping of paths (which can become quite numerous and
    # long) to integer keys, so they can be used in multiple locations
    # This should be in the format:
    # {
    #     'path': PathRecord instance
    # }
    _path_records = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._uid_b64_references = {}

    def path_rec(self, path):
        """ Creates a singleton PathRecord for the path provided
        """

        # Just so we can allow recursive calls into object
        if isinstance(path, PathRecord):
            return path

        # And this is an actual pathlib.Path so let's get a PathRecord for it
        path_str = str(path)
        if path_str not in self._path_records:
            self._path_records[path_str] = PathRecord(path_str)
        return self._path_records[path_str]

    def __setitem__(self, path, nexus_record):
        """ Creates a PathRecord from the path and sets the cached NexusRecord
            for that path to nexus_record. (Inserts the nexus_record into the
            path lookup cache)
        """
        path_rec = self.path_rec(path)

        super().__setitem__(path_rec, nexus_record)

        path_rec.uid_b64 = nexus_record.uuid
        self._uid_b64_references[path_rec.uid_b64] = path_rec

    def __getitem__(self, path):
        """ Returns the the PathRecord for a given path (assuming
            it's in the cache)
        """
        path_rec = self.path_rec(path)
        return super().__getitem__(path_rec)

    def __contains__(self, path):
        """ Checks if we already have a reference to the path
        """
        path_rec = self.path_rec(path)
        return super().__contains__(path_rec)

    def __delitem__(self, path):
        """ Removes a PathRecord reference from the cache
        """
        path_rec = self.path_rec(path)
        super().__delitem__(path_rec)
        if path_rec.uid_b64:
            del self._uid_b64_references[path_rec.uid_b64]

    def by_uid(self, uid_b64, default=None):
        """ Gets a cached record by uid_b64 if available
        """
        path_rec = self._uid_b64_references.get(uid_b64, None)
        if not path_rec:
            return default
        return self[path_rec]

    def relocated(self, path_old, path_new):
        """ Amend a previously cached path location to a new
            location
        """
        if path_old not in self:
            return
        self[path_new] = self.get(path_old)
        del self[path_old]

    def relocated_uid(self, uid_b64, path_new):
        """ Amend a previously cached object to a new location
        """

        # Create the new path record
        path_rec_new = self.path_rec(path_new)

        # Get the current PathRecord pointer via the uid_b64
        path_rec = self._uid_b64_references.get(uid_b64)

        # Removes the record from the cache (also removes the uid_b64
        # refence)
        nexus_record = self.pop(path_rec)

        # Sets the new value
        self[path_rec_new] = nexus_record

        return nexus_record

    def pop(self, path, default=None):
        """ Removes a path from the dict if it exists. Returns the value
            removed or returns default if not exists
        """
        if path not in self:
            return default
        nexus_record = self[path]
        del self[path]
        return nexus_record

RECORD_CACHE = RecordCache()


def simplify(v):
    """ This ensures that that the records that pass through
        this particular function are down to their basic primitive
        types. This makes all records possible to send through
        serializers like JSON
    """
    if hasattr(v, 'dict_'):
        v = v.dict_()

    if isinstance(v, ruamel.yaml.comments.CommentedMap):
        v = dict(v)

    if isinstance(v, dict):
        vp = {}
        for k, v in v.items():
            vp[k] = simplify(v)
        return vp

    elif isinstance(v, datetime.datetime):
        v = v.isoformat()

    elif isinstance(v, list):
        return [simplify(e) for e in v]

    elif hasattr(v, 'list_'):
        return [simplify(e) for e in v]

    return v


#####################################################
# YAML Handling
#####################################################

# Global YAML Serializer
yaml = ruamel.yaml.YAML()
yaml.explicit_end=False
yaml.compact(seq_seq=False)

def yaml_dumps(data):
    io_buf = io.StringIO()
    yaml.dump(data, io_buf)
    io_buf.seek(0)
    yaml_str = str(io_buf.read())
    # Strip out the end-of-document marker
    if yaml_str.endswith('...\n'):
           return yaml_str[:-4]
    return yaml_str

def yaml_dump_file(data, fpath):
    """ When we dump a file, we need to do so in two steps just in case
        something weird happens. In one bug #8688, we were getting 0 byte
        files. This just tightens up the handling so that the files are
        saved and operated on in a way that tries its best to avoid
        write errors
    """

    # Create a temp file
    for i in range(100):
        temp_fpath = fpath.parent / ( fpath.name + f'.temp{i}' )
        if not temp_fpath.exists():
            break
    else:
        raise Exception(f"Unable to create a temp file for {fpath}")

    # Dump the data to this temp file
    with open(temp_fpath,'w') as fh:
        yaml.dump(data, fh)

    # If the filesize is 0, there's an issue so we'll just drop out
    if temp_fpath.stat().st_size == 0:
        raise Exception(f"Attempting to rewrite {fpath} with 0 byte output. YAML data broken?")

    # No exceptions raised so we're going to make a backup copy of the
    # original file data as a '*.bak'
    if fpath.exists():
        backup_fpath = fpath.parent / ( fpath.name + '.bak' )
        shutil.copy(str(fpath), str(backup_fpath))

    # Then move the new file over
    temp_fpath.rename(fpath)


def yaml_loads(buf):
    return yaml.load(buf)

def yaml_load(fh):
    return yaml.load(fh)

def yaml_load_file(fpath):
    with open(fpath,'r') as fh:
        data = yaml.load(fh)
    return data
