# DataSharing Platform

This repository contains the `DataSharingClient` class, which allows you to interact with data stored in S3 and perform queries using DuckDB. This guide will help you set up your environment, configure your credentials, and use the various functionalities provided by the `DataSharingClient`.

## LLM Partner

LLMs can be a helpful partner when working with this repository. You can copy the contents of `LLMPartner.txt` and add it into a chat assistant such as ChatGPT, Claude, Gemini, or any other provider you prefer. Your LLM partner can help out with syntax for SQL queries, provide guidance on using DuckDB within the DataSharingClient, and answer general questions about the code and your analysis. 

## Setup Instructions

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- Virtual environment (`venv`) module

### Setting Up the Virtual Environment

#### Windows

1. **Open Command Prompt** and navigate to your project directory:

    ```bash
    cd path\to\your\project
    ```

2. **Create a virtual environment** with a custom name (e.g., `myenv`):

    ```bash
    python3 -m venv newvenv
    ```

3. **Activate the virtual environment**:

    ```bash
    source newvenv/bin/activate
    ```

4. **Install the required dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

#### Linux

1. **Open Terminal** and navigate to your project directory:

    ```bash
    cd path/to/your/project
    ```

2. **Create a virtual environment** with a custom name (e.g., `myenv`):

    ```bash
    python3 -m venv myenv
    ```

3. **Activate the virtual environment**:

    ```bash
    source myenv/bin/activate
    ```

4. **Install the required dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

### Configuring Your Environment

1. **Copy the example environment file** and create a new `.env` file:

    ```bash
    cp .env.example .env
    ```

2. **Open the `.env` file** and input your credentials:

    ```
    OCEAN_USERNAME=your_username
    OCEAN_PASSWORD=your_password
    ```

# Example Usage

## Setting Up the Environment

1. **Run the first code block to set all imports and initialize the client:**

    ```python
    # Initialize the client using credentials from .env file
    client = DataSharingClient()
    ```

2. **For VSCode users:** You can work directly in the `.ipynb` file without running the command line by selecting your virtual environment after clicking **Select Kernel** in the top right corner.

## Initialization with Different Config Options

1. **Default Initialization:**
    ```python
    client = DataSharingClient()
    ```

2. **Custom Initialization with DuckDB Parameters:**
    ```python
    duckdb_path = "path/to/file/nameofyourduckdbfile.duckdb"
    client = DataSharingClient(duckdb_region="us-east-1", duckdb_path=duckdb_path)
    ```

## Creating a View

1. **Creating a View from S3 URI:**
    ```python
    # Example: Creating a view from a Parquet file in S3
    s3_uri = "s3://your-bucket-name/path/to/yourfile.parquet"
    view_name = "your_view_name"
    client.create_view(s3_uri, view_name)
    ```

2. **Creating a View from Local Path:**
    ```python
    # Example: Creating a view from a Parquet file in local storage
    local_path = "path/to/local/file/yourfile.parquet"
    view_name = "your_view_name"
    client.create_view(local_path, view_name)
    ```

## Querying the View

1. **Querying the View to Count the Records:**
    ```python
    # Example: Querying the view to count the records
    query = "SELECT COUNT(*) FROM your_view_name;"
    result_df = client.query(query)
    print(result_df)
    ```

2. **Creating a New Table from a Query:**
    ```python
    # Example: Creating a new table from a query
    query = "SELECT * FROM your_view_name WHERE your_column > some_value;"
    new_table_name = "new_table_name"
    client.query(query, new_table_name)
    ```

## Listing All Tables

```python
# Example: Listing all tables and views
tables = client.list_tables()
print(tables)