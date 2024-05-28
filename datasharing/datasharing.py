# datasharing/datasharing.py

import os
import requests
import json
import duckdb
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from dotenv import load_dotenv

class DataSharingClient:
    def __init__(self, username=None, password=None):
        # Load environment variables from the .env file
        load_dotenv()

        # Retrieve credentials from environment variables if not provided
        self.username = username or os.getenv("USERNAME")
        self.password = password or os.getenv("PASSWORD")

        if not self.username or not self.password:
            raise ValueError("Username and password must be provided either as arguments or in the .env file")

        self.config = {
            "region": "us-east-1",
            "userPoolId": "us-east-1_4m9MAAEMh",
            "clientId": "ji5riv8se44v47u82pfagno4u",
            "identityPoolId": "us-east-1:b6463bb7-a820-4003-9d61-d8295bfc0d07",
            "bucketName": "crossbowbuckettest"
        }
        self.id_token = None
        self.access_token = None
        self.temporary_credentials = None
        self.conn = None

        self.authenticate_user()
        self.obtain_temporary_credentials()
        self.setup_duckdb()

    def authenticate_user(self):
        auth_url = f"https://cognito-idp.{self.config['region']}.amazonaws.com/"
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth"
        }
        auth_data = {
            "AuthParameters": {
                "USERNAME": self.username,
                "PASSWORD": self.password
            },
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": self.config["clientId"]
        }

        response = requests.post(auth_url, headers=headers, json=auth_data)
        response_data = response.json()

        if response.status_code == 200:
            self.id_token = response_data["AuthenticationResult"]["IdToken"]
            self.access_token = response_data["AuthenticationResult"]["AccessToken"]
            print("Authentication successful.")
        else:
            print("Authentication failed:", response_data)

    def obtain_temporary_credentials(self):
        cognito_identity_client = boto3.client('cognito-identity', region_name=self.config["region"])

        logins = {
            f'cognito-idp.{self.config["region"]}.amazonaws.com/{self.config["userPoolId"]}': self.id_token
        }

        response = cognito_identity_client.get_id(
            IdentityPoolId=self.config["identityPoolId"],
            Logins=logins
        )

        identity_id = response['IdentityId']

        response = cognito_identity_client.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins=logins
        )

        self.temporary_credentials = response['Credentials']
        print("Temporary credentials obtained.")

    def setup_duckdb(self):
        self.conn = duckdb.connect(database=':memory:', read_only=False)
        self.conn.execute("INSTALL httpfs;")
        self.conn.execute("LOAD httpfs;")
        self.conn.execute(f"SET s3_region='{self.config['region']}';")
        self.conn.execute(f"SET s3_access_key_id='{self.temporary_credentials['AccessKeyId']}';")
        self.conn.execute(f"SET s3_secret_access_key='{self.temporary_credentials['SecretKey']}';")
        self.conn.execute(f"SET s3_session_token='{self.temporary_credentials['SessionToken']}';")
        print("DuckDB setup complete.")

    def create_view(self, path, view_name):
        if path.startswith("s3://"):
            self._create_view_from_s3(path, view_name)
        else:
            self._create_view_from_local(path, view_name)
        print(f"View {view_name} created.")

    def _create_view_from_s3(self, s3_path, view_name):
        file_extension = s3_path.split('.')[-1].lower()

        if file_extension == "csv":
            query = f"CREATE VIEW {view_name} AS SELECT * FROM read_csv_auto('{s3_path}')"
        elif file_extension == "parquet":
            query = f"CREATE VIEW {view_name} AS SELECT * FROM read_parquet('{s3_path}')"
        elif file_extension == "json":
            query = f"CREATE VIEW {view_name} AS SELECT * FROM read_json_auto('{s3_path}')"
        else:
            raise ValueError(f"Unsupported file type: {file_extension}")

        self.conn.execute(query)

    def _create_view_from_local(self, file_path, view_name):
        file_extension = file_path.split('.')[-1].lower()

        if file_extension == "csv":
            query = f"CREATE VIEW {view_name} AS SELECT * FROM read_csv_auto('{file_path}')"
        elif file_extension == "parquet":
            query = f"CREATE VIEW {view_name} AS SELECT * FROM read_parquet('{file_path}')"
        elif file_extension == "json":
            query = f"CREATE VIEW {view_name} AS SELECT * FROM read_json_auto('{file_path}')"
        else:
            raise ValueError(f"Unsupported file type: {file_extension}")

        self.conn.execute(query)

    def query_view(self, query, new_table_name=None):
        if new_table_name:
            self.conn.execute(f"CREATE TABLE {new_table_name} AS {query}")
            print(f"Table {new_table_name} created from query.")
        else:
            result_df = self.conn.execute(query).fetchdf()
            print("Query executed successfully.")
            return result_df

    def list_tables(self):
        query = """
        SELECT table_name, table_type 
        FROM information_schema.tables 
        WHERE table_schema='main'
        """
        tables = self.conn.execute(query).fetchall()
        return tables

    def export_tables(self, table_names, output_dir, file_format):
        os.makedirs(output_dir, exist_ok=True)

        if file_format in ["parquet", "csv"]:
            for table_name in table_names:
                file_name = f"{table_name}.{file_format}"
                file_path = os.path.join(output_dir, file_name)

                if file_format == "parquet":
                    self.conn.execute(
                        f"COPY (SELECT * FROM {table_name}) TO '{file_path}' (FORMAT 'parquet')"
                    )
                elif file_format == "csv":
                    self.conn.execute(
                        f"COPY (SELECT * FROM {table_name}) TO '{file_path}' (HEADER, DELIMITER ',')"
                    )
        else:
            raise ValueError(f"Unsupported file format: {file_format}")
