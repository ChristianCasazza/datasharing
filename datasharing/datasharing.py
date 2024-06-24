import os
import requests
import json
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from dotenv import load_dotenv
import ibis
import s3fs
import pandas as pd
import urllib.parse

class DataSharingClient:
    def __init__(self, duckdb_region=None, username=None, password=None, debug=False, duckdb_path=None):
        self.debug = debug  # Set the debug flag

        # Load environment variables from the .env file
        load_dotenv()

        # Retrieve credentials from environment variables if not provided
        self.username = username or os.getenv("OCEAN_USERNAME")
        self.password = password or os.getenv("OCEAN_PASSWORD")

        if not self.username or not self.password:
            raise ValueError("Username and password must be provided either as arguments or in the .env file")

        self.config = {
            "region": "us-east-1",  # Default region for Cognito
            "duckdb_region": duckdb_region or "eu-west-3",  # Default to eu-west-3 if not specified
            "userPoolId": "us-east-1_EgvUvAJoP",
            "clientId": "6elhn5n4tt1p4dfa41ulljmbp3",
            "identityPoolId": "us-east-1:60dd28e7-c15f-4108-b2a1-a672c12c9756",
            "bucketName": "thecrossbowbucket-1717040468242"
        }
        self.id_token = None
        self.access_token = None
        self.refresh_token = None
        self.temporary_credentials = None
        self.conn = None
        self.s3_client = None
        self.cognito_identity_client = None
        self.duckdb_path = duckdb_path  # Path for persistent DuckDB database

        self.authenticate_user()
        self.obtain_temporary_credentials()
        self.setup_ibis_duckdb()

        if not self.debug:
            print("It's data time!")
            print(f'You can query datasets in the "{self.config["duckdb_region"]}" region')

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
            if 'ChallengeName' in response_data and response_data['ChallengeName'] == 'SOFTWARE_TOKEN_MFA':
                mfa_code = input("Enter the MFA code from your authenticator app: ")
                self.respond_to_auth_challenge(response_data['Session'], mfa_code)
            else:
                self.id_token = response_data["AuthenticationResult"]["IdToken"]
                self.access_token = response_data["AuthenticationResult"]["AccessToken"]
                self.refresh_token = response_data["AuthenticationResult"]["RefreshToken"]
                if self.debug:
                    print("Authentication successful.")
        else:
            print("Authentication failed:", response_data)

    def respond_to_auth_challenge(self, session, mfa_code):
        auth_url = f"https://cognito-idp.{self.config['region']}.amazonaws.com/"
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.RespondToAuthChallenge"
        }
        challenge_data = {
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ClientId": self.config["clientId"],
            "Session": session,
            "ChallengeResponses": {
                "USERNAME": self.username,
                "SOFTWARE_TOKEN_MFA_CODE": mfa_code
            }
        }

        response = requests.post(auth_url, headers=headers, json=challenge_data)
        response_data = response.json()

        if response.status_code == 200:
            self.id_token = response_data["AuthenticationResult"]["IdToken"]
            self.access_token = response_data["AuthenticationResult"]["AccessToken"]
            self.refresh_token = response_data["AuthenticationResult"]["RefreshToken"]
            if self.debug:
                print("MFA authentication successful.")
        else:
            print("MFA authentication failed:", response_data)

    def obtain_temporary_credentials(self):
        if not self.cognito_identity_client:
            self.cognito_identity_client = boto3.client('cognito-identity', region_name=self.config["region"])

        logins = {
            f'cognito-idp.{self.config["region"]}.amazonaws.com/{self.config["userPoolId"]}': self.id_token
        }

        try:
            if self.debug:
                print("Getting identity ID...")
            response = self.cognito_identity_client.get_id(
                IdentityPoolId=self.config["identityPoolId"],
                Logins=logins
            )
            identity_id = response['IdentityId']
            if self.debug:
                print(f"Identity ID obtained: {identity_id}")

            if self.debug:
                print("Getting OpenID token...")
            open_id_response = self.cognito_identity_client.get_open_id_token(
                IdentityId=identity_id,
                Logins=logins
            )
            open_id_token = open_id_response['Token']
            if self.debug:
                print("OpenID token obtained.")

            if self.debug:
                print("Getting credentials for identity...")
            credentials_response = self.cognito_identity_client.get_credentials_for_identity(
                IdentityId=identity_id,
                Logins=logins
            )

            self.temporary_credentials = credentials_response['Credentials']
            if self.debug:
                print("Temporary credentials obtained.")
        except Exception as e:
            print(f"Error obtaining temporary credentials: {e}")

        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=self.temporary_credentials['AccessKeyId'],
            aws_secret_access_key=self.temporary_credentials['SecretKey'],
            aws_session_token=self.temporary_credentials['SessionToken'],
            region_name=self.config["duckdb_region"]
        )

    def setup_ibis_duckdb(self):
        # Use DuckDB as the Ibis backend
        if self.duckdb_path:
            # Use an existing DuckDB file or create a new one at the specified path
            self.ibis_conn = ibis.connect(f'duckdb://{self.duckdb_path}')
        else:
            # Use an in-memory DuckDB instance
            self.ibis_conn = ibis.connect('duckdb://:memory:')

        fs = s3fs.S3FileSystem(
            key=self.temporary_credentials['AccessKeyId'],
            secret=self.temporary_credentials['SecretKey'],
            token=self.temporary_credentials['SessionToken'],
            client_kwargs={'region_name': self.config['duckdb_region']}
        )

        self.ibis_conn.raw_sql("INSTALL httpfs;")
        self.ibis_conn.raw_sql("LOAD httpfs;")
        self.ibis_conn.raw_sql(f"SET s3_access_key_id='{self.temporary_credentials['AccessKeyId']}';")
        self.ibis_conn.raw_sql(f"SET s3_secret_access_key='{self.temporary_credentials['SecretKey']}';")
        self.ibis_conn.raw_sql(f"SET s3_session_token='{self.temporary_credentials['SessionToken']}';")
        self.ibis_conn.raw_sql(f"SET s3_region='{self.config['duckdb_region']}';")
        self.ibis_conn.register_filesystem(fs)
        if self.debug:
            print("DuckDB setup complete with Ibis and S3FS.")

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

        self.ibis_conn.raw_sql(query)

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

        self.ibis_conn.raw_sql(query)

    def query(self, query, new_table_name=None):
        if isinstance(query, str):
            if new_table_name:
                # Create a new table from the query
                create_table_query = f"CREATE TABLE {new_table_name} AS {query}"
                self.ibis_conn.raw_sql(create_table_query)
            else:
                return self.ibis_conn.raw_sql(query).df()
        elif isinstance(query, ibis.expr.types.Table):
            if new_table_name:
                # Create a new table from the Ibis table expression
                create_table_query = f"CREATE TABLE {new_table_name} AS {query.compile()}"
                self.ibis_conn.raw_sql(create_table_query)
            else:
                return query.execute()
        else:
            raise TypeError("Query must be a string or an Ibis table expression.")

    def export_tables(self, table_names, output_dir, file_format='csv'):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        for table_name in table_names:
            if isinstance(table_name, ibis.expr.types.Table):
                # If the table name is an Ibis table expression
                table_expr = table_name
            elif isinstance(table_name, ibis.expr.types.Column):
                # If the table name is a column expression, convert it to a table
                table_expr = table_name.to_projection()
            elif isinstance(table_name, str):
                # If the table name is a string, get the table from DuckDB
                table_expr = self.ibis_conn.table(table_name)
            else:
                raise TypeError("Table name must be either a string, an Ibis table expression, or an Ibis column expression.")
            
            output_path = os.path.join(output_dir, f"{table_expr.op().name}.{file_format}")

            if file_format == 'csv':
                self.ibis_conn.raw_sql(f"COPY ({table_expr.compile()}) TO '{output_path}' WITH (FORMAT CSV, HEADER TRUE);")
            elif file_format == 'parquet':
                self.ibis_conn.raw_sql(f"COPY ({table_expr.compile()}) TO '{output_path}' WITH (FORMAT PARQUET);")
            else:
                raise ValueError(f"Unsupported file format: {file_format}")

        print(f"Tables exported to {output_dir}.")

    def download_dataset(self, s3_uri, local_path):
        parsed_url = urllib.parse.urlparse(s3_uri)
        bucket_name = parsed_url.netloc
        object_key = parsed_url.path.lstrip('/')

        try:
            self.s3_client.download_file(bucket_name, object_key, local_path)
            print(f"Downloaded {s3_uri} to {local_path}")
        except Exception as e:
            print(f"Error downloading dataset: {e}")

