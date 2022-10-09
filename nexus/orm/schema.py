from nexus.log import log

from nexus.orm.common import *
from nexus.orm.field import *

class NexusSchema:
    version = None
    columns = None

    def __init__(self, version, **kwargs):
        self.version = version

        self.columns = {
            'uuid': NexusField('Database Universal Unique Record ID', default=None),
        }
        for name, spec in kwargs.items():
            self.columns[name] = spec
            spec.name = name

    @classmethod
    def from_yaml(cls, buf):
        schema_data = yaml().load(buf)

        version = None
        columns = {}

        for field, spec_data in schema_data.items():
            if field == 'version':
                version = spec_data
            else:
                columns[field] = NexusField(**spec_data)

        return cls(version, **columns)

    def yaml(self):
        """ This should return the columns converted into a ruamel.yaml.YAML data structure
        """
        data = ruamel.yaml.CommentedMap()
        data.yaml_set_start_comment('Database version. This key should always be present')
        data['version'] = self.version

        for field, spec in self.columns.items():
            data[field] = spec.default
            if spec.help:
                data.yaml_set_comment_before_after_key(
                      key=field,
                      before="\n"+spec.help
                  )

        return data

    def migrate(self, source):
        """ Perform an auto migrate of data from one version to another.
        """

        # We want to do a full copy since we may clobber
        buf = ruamel.yaml.compat.BytesIO()
        yaml().dump(source, buf)
        migrated = yaml().load(buf.getvalue())

        # If we're already ahead in versions, we'll just return the
        # cloned data structure
        if source['version'] >= self.version:
            return migrated

        # So we're behind, let's just copy the migrated over
        for field, spec in self.columns.items():
            if field in migrated:
                continue
            migrated[field] = spec.default
            if spec.help:
                migrated.yaml_set_comment_before_after_key(
                      key=field,
                      before="\n"+spec.help
                  )

        # Bump version
        migrated['version'] = self.version

        return migrated 


    def __getitem__(self, k):
        return self.columns[k]

