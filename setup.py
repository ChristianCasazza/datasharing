from setuptools import setup, find_packages

setup(
    name="data_sharing",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "boto3",
        "duckdb",
        "requests",
        "python-dotenv",
        "jupyter"
    ],
    author="Christian Casazza",
    author_email="christian@oceanprotocol.com",
    description="Query data from S3",
    url="https://github.com/ChristianCasazza/datasharing",
)
