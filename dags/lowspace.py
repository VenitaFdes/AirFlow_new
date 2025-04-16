import sys
import logging
logging.basicConfig(level=logging.INFO)  # Ensure logging is properly configured
logging.info("Lowspace DAG is being parsed")

from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime, timedelta
from newws import fetch_nvd_data, transform_data, save_to_clickhouse  
import tempfile
import json
import os
import traceback  # Import traceback for detailed error logging

def fetch_data_task(**kwargs):
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        data = fetch_nvd_data(api_url)
        if not data:
            raise ValueError("No data fetched from the API.")
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json') as f:
            json.dump(data, f)
            temp_path = f.name
        kwargs['ti'].xcom_push(key='raw_data_path', value=temp_path)
    except Exception as e:
        logging.error(f"Error in fetch_data_task: {e}")
        traceback.print_exc()
        raise

def transform_data_task(**kwargs):
    raw_data_path = kwargs['ti'].xcom_pull(key='raw_data_path')
    try:
        with open(raw_data_path, 'r') as f:
            raw_data = json.load(f)
        logging.info(f"Raw data size: {len(raw_data)} records")  # Log data size
        transformed_data = transform_data(raw_data)
        if not transformed_data:
            raise ValueError("Transformation resulted in no data.")
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json') as f:
            json.dump(transformed_data, f)
            temp_path = f.name
        kwargs['ti'].xcom_push(key='transformed_data_path', value=temp_path)
    except Exception as e:
        logging.error(f"Error in transform_data_task: {e}")
        traceback.print_exc()
        raise
    finally:
        if os.path.exists(raw_data_path):
            os.remove(raw_data_path)  # Clean up

def save_data_task(**kwargs):
    transformed_data_path = kwargs['ti'].xcom_pull(key='transformed_data_path')
    try:
        with open(transformed_data_path, 'r') as f:
            transformed_data = json.load(f)
        save_to_clickhouse(transformed_data)
    except Exception as e:
        logging.error(f"Error in save_data_task: {e}")
        traceback.print_exc()
        raise
    finally:
        if os.path.exists(transformed_data_path):
            os.remove(transformed_data_path)  # Clean up

default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 3,
}

with DAG(
    'lowspace',
    default_args=default_args,
    description='A pipeline to fetch, transform, and save NVD data',
    schedule_interval='*/10 * * * *',
    start_date=datetime(2023, 1, 1),
    catchup=False,
) as dag:

    fetch_data = PythonOperator(
        task_id='fetch_data',
        python_callable=fetch_data_task,
    )

    transform_data_op = PythonOperator(
        task_id='transform_data',
        python_callable=transform_data_task,
        execution_timeout=timedelta(minutes=10),  
    )

    save_data = PythonOperator(
        task_id='save_data',
        python_callable=save_data_task,
        execution_timeout=timedelta(minutes=10), 
        retries=1,  
        retry_delay=timedelta(minutes=5),  
    )

    fetch_data >> transform_data_op >> save_data