import pathlib
import logging
import time

from izaber import config
from izaber.startup import request_initialize, initializer

from nexus.orm import *

from nexus.domain.db.users import NexusUsers
from nexus.domain.db.roles import NexusRoles
from nexus.domain.db.cookies import NexusCookies

log = logging.getLogger('nexus-db')

##################################################
# File Database Handler
##################################################

class DB(NexusDB):
    _collections = {
        'users': NexusUsers,
        'roles': NexusRoles,
        'cookies': NexusCookies,
    }

##################################################################
# Authenticated ORM methods
##################################################################

    def query_authorized(self,
                  login,
                  collection_type,
                  conditions=None,
                  fields=None,
                  sort=None,
                  limit=None,
                  page_index=0
              ):
        # Amend the input values
        collection_cls = self.get_collection_type(collection_type)

        # Amend for security if required
        kwargs = collection_cls.authorize(
                          self, login, 'query',
                          collection_type=collection_type,
                          conditions=conditions,
                          sort=sort,
                          limit=limit,
                          page_index=page_index,
                      )
        return self.query(**kwargs)


    def create_authorized(self,
                  login,
                  parent_uid_b64,
                  collection_attrib,
                  data_rec
                  ):
        # Now execute!
        parent = self.get(parent_uid_b64)

        # Amend the input values
        collection_cls = self.get_collection_type(collection_attrib)

        # Amend for security if required
        kwargs = collection_cls.authorize(
                          self, login, 'create',
                          parent_uid_b64=parent_uid_b64,
                          collection_attrib=collection_attrib,
                          data_rec=data_rec
                      )

        return self.create(**kwargs)

    def update_authorized(self,
                  login,
                  uid_b64s,
                  data_rec
                  ):

        for uid_b64 in uid_b64s:

            record = self.get(uid_b64)
            if not record: continue

            # Amend the input values
            collection_cls = self.get_collection_type(record.parent_.collection_type_)

            # Amend for security if required
            kwargs = collection_cls.authorize(
                          self, login, 'update',
                          uid_b64s=[uid_b64],
                          data_rec=data_rec
                      )

            self.update(**kwargs)

    def upsert_authorized(self,
                  login,
                  parent_uid_b64,
                  collection_attrib,
                  data_rec
                  ):
        # Now execute!
        parent = self.get(parent_uid_b64)

        # Does the record already exist?
        record_obj = parent.get_collection_(collection_attrib)
        if record_obj:
            return self.update_authorized(
                              login,
                              [record_obj.uuid],
                              data_rec
                          )


        # Nope, so we need to add it
        else:
            return self.create_authorized(
                              login,
                              parent_uid_b64,
                              collection_attrib,
                              data_rec
                          )


    def delete_authorized(self,
                  login,
                  uid_b64s,
                  ):

        for uid_b64 in uid_b64s:
            record = self.get(uid_b64)
            if not record: continue

            # Amend the input values
            collection_cls = self.get_collection_type(record.parent_.collection_type_)

            # Amend for security if required
            kwargs = collection_cls.authorize(
                          self, login, 'delete',
                          uid_b64s=[uid_b64],
                      )

            self.delete(**kwargs)

    def vacuum_(self):
        """ Periodic should be called to remove old cruft
        """
        self.cookies.vacuum_()
        self.roles.vacuum_()
        self.reindex_uuids()

##################################################################
#
##################################################################

db = DB()

@initializer('nexus-db')
def load_config(**options):
    request_initialize('config',**options)

    # Let's hope someone's configured a DB directory in their
    # izaber.yaml file
    try:
        db_path = pathlib.Path(config.nexus.db.path).resolve()

    except KeyError:
    # Unfortunately not so let's see if we can generate the data
    # manually
        current_fpath = pathlib.Path(__file__)
        data_path = current_fpath.parent.parent.parent.parent.parent / "data"
        if not data_path.exists():
            raise Exception(f"Expected data_path at '{data_path}'. However, nothing exists there!")
        db_path = data_path / "db"

    # Let's index if possible
    try:
        start_time = time.time()
        db.load_config(db_path)
        end_time = time.time()
        elapsed = end_time - start_time
        log.info(f"Database initialization/review took {elapsed}s")
    except Exception as ex:
        log.error(f"Unable to reindex database because {ex}")
        import traceback
        traceback.print_exc()



