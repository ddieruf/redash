import logging
import os
import zipfile
import io

from base64 import b64decode
from tempfile import NamedTemporaryFile

from redash.query_runner import BaseQueryRunner, register
from redash.utils import json_dumps, json_loads, JSONEncoder

logger = logging.getLogger(__name__)

try:
    import cassandra
    from cassandra.cluster import Cluster
    from cassandra.auth import PlainTextAuthProvider

    enabled = True
except ImportError as error:
    enabled = False


def _cleanup_secure_bundle_file(secure_bundle_path):
    if secure_bundle_path:
        os.remove(secure_bundle_path)


class CassandraJSONEncoder(JSONEncoder):
    def default(self, o, sortedset=None):
        if isinstance(o, sortedset):
            return list(o)
        return super(CassandraJSONEncoder, self).default(o)


class AstraDB(BaseQueryRunner):
    noop_query = "select release_version from system.local"

    @classmethod
    def enabled(cls):
        return enabled

    @classmethod
    def configuration_schema(cls):
        return {
            "type": "object",
            "properties": {
                "clientId": {"type": "string", "title": "Client Id"},
                "clientSecret": {"type": "string", "title": "Client Secret"},
                "secureBundleFile": {
                    "type": "string",
                    "title": "Secure Bundle File"
                },
                "keySpace": {"type": "string", "title": "Key Space"},
                "timeout": {"type": "number", "title": "Timeout", "default": 10},
            },
            "order": ["clientId", "clientSecret", "secureBundleFile", "keySpace", "timeout"],
            "required": ["clientId", "clientSecret", "secureBundleFile"],
            "secret": ["secureBundleFile"],
        }

    @classmethod
    def type(cls):
        return "astraDB"

    def get_schema(self, get_stats=False):
        logger.debug("Using Cassandra driver version %s", cassandra.__version__)

        query = """
        SELECT table_name, column_name FROM system_schema.columns WHERE keyspace_name ='{}';
        """.format(
            self.configuration["keySpace"]
        )

        logger.debug("Retrieving schema details, %s", query)
        results, error = self.run_query(query, None)
        results = json_loads(results)

        schema = {}
        for row in results["rows"]:
            table_name = row["table_name"]
            column_name = row["column_name"]
            if table_name not in schema:
                schema[table_name] = {"name": table_name, "columns": []}
            schema[table_name]["columns"].append(column_name)

        return list(schema.values())

    def run_query(self, query, user):
        logger.debug("Using Cassandra driver version %s", cassandra.__version__)

        cluster = None
        secure_bundle_path = self._generate_secure_bundle_file()

        cloud_config = {
            'secure_connect_bundle': secure_bundle_path
        }
        auth_provider = PlainTextAuthProvider(self.configuration["clientId"], self.configuration["clientSecret"])
        cluster = Cluster(
            cloud=cloud_config,
            auth_provider=auth_provider
        )

        logger.debug("Attempting to connect with cluster")
        session = cluster.connect()

        try:
            session.default_timeout = self.configuration.get("timeout", 10)
            session.set_keyspace(self.configuration["keySpace"])
            logger.debug("Running query: %s", query)
            result = session.execute(query)
            _cleanup_secure_bundle_file(secure_bundle_path)

            logger.debug("Building response")
            column_names = result.column_names

            columns = self.fetch_columns([(c, "string") for c in column_names])

            rows = [dict(zip(column_names, row)) for row in result]

            data = {"columns": columns, "rows": rows}
            error = None
            json_data = json_dumps(data, cls=CassandraJSONEncoder)
            logger.debug("Query successful")
        finally:
            cluster.shutdown()

        return json_data, error

    def _generate_secure_bundle_file(self):
        encoded_bytes = self.configuration.get("secureBundleFile", None)

        if encoded_bytes:
            with NamedTemporaryFile(mode='wb', delete=False) as bundle:
                logger.debug("Decoding bytes")
                cert_bytes = b64decode(encoded_bytes)
                logger.debug("Writing bytes")
                bundle.write(io.BytesIO(cert_bytes).getbuffer())

            logger.debug("Validating file as zip")
            with zipfile.ZipFile(bundle.name) as zip_archive:
                zip_archive.testzip()
                logger.debug("  There are %s files present in archive", len(zip_archive.filelist))

            return bundle.name
        raise Exception("No secure bundle could be found")


register(AstraDB)
