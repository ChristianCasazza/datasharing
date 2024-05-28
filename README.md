# DataSharing Platform

This repository contains the `DataSharingClient` class, which allows you to interact with data stored in S3 and perform queries using DuckDB. This guide will help you set up your environment, configure your credentials, and use the various functionalities provided by the `DataSharingClient`.

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
    python -m venv myenv
    ```

3. **Activate the virtual environment**:

    ```bash
    myenv\Scripts\activate
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
    USERNAME=your_username
    PASSWORD=your_password
    ```

### Example Usage

#### Setting Up the Environment

1. **Run the first code block to set all imports and initialize the client:**

    ```python
    # Import necessary libraries and set up the environment
    import os
    import sys
    from dotenv import load_dotenv

    # Load environment variables from the .env file
    load_dotenv()

    # Add the project root to sys.path
    notebook_dir = os.path.dirname(os.path.abspath('data.ipynb'))
    project_root = os.path.abspath(os.path.join(notebook_dir, '..'))
    if project_root not in sys.path:
        sys.path.append(project_root)

    from datasharing.datasharing import DataSharingClient

    # Initialize the client using credentials from .env file
    client = DataSharingClient()

    # OR

    # Initialize the client with direct input credentials
    # username = "your_username"
    # password = "your_password"
    # client = DataSharingClient(username=username, password=password)
    ```

2. **For VSCode users:** You can work directly in the `.ipynb` file without running the command line by selecting your virtual environment after clicking **Select Kernel** in the top right corner.

#### 1. Creating a View

    ```python
    # Example: Creating a view from a Parquet file in S3
    s3_uri = "s3://your-bucket-name/path/to/yourfile.parquet"
    view_name = "your_view_name"
    client.create_view(s3_uri, view_name)
    ```

#### 2. Querying the View

    ```python
    # Example: Querying the view to count the records
    query = "SELECT COUNT(*) FROM your_view_name;"
    result_df = client.query_view(query)
    print(result_df)

    # Example: Creating a new table from a query
    query = "SELECT * FROM your_view_name WHERE your_column > some_value;"
    new_table_name = "new_table_name"
    client.query_view(query, new_table_name)
    ```

#### 3. Listing All Tables

    ```python
    # Example: Listing all tables and views
    tables = client.list_tables()
    print(tables)
    ```

#### 4. Exporting Tables

    ```python
    # Example: Exporting tables to CSV
    table_names = ["your_view_name", "new_table_name"]
    output_dir = "/path/to/output"

    # Export to CSV
    client.export_tables(table_names, output_dir, "csv")

    # Export to Parquet
    client.export_tables(table_names, output_dir, "parquet")
    ```

