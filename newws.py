import requests
import json
import csv
import os
from itertools import product
import clickhouse_connect
from datetime import datetime  
import traceback  # Import the traceback module
import pandas as pd  
import numpy as np
from airflow.models import Variable
 
 
def fetch_nvd_data(api_url, params=None):
    data = []
    start_index = 200
    results_per_page = 2000
    max_records = 200
 
    while True:
        if not params:
            params = {}
        params.update({"startIndex": start_index, "resultsPerPage": results_per_page})
 
        try:
            response = requests.get(api_url, params=params)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data: {e}")
            break
 
        # print(f"API Response Status: {response.status_code}")
        # print(f"API Response Content: {response.text[:500]}")
 
        result = response.json()
        records = result.get("vulnerabilities", [])
        # print(records)
 
        if not records:
            print("No more records to fetch.")
            break
 
        data.extend(records)
        print(f"Fetched {len(records)} records. Total: {len(data)}")
 
        if len(data) >= max_records:
            print(f"Reached max record limit of {max_records} records.")
            data = data[:max_records]
            break
 
        start_index += results_per_page
 
        if len(records) < results_per_page:
            break
 
    return data
 
 
def flatten_cve(cve_entry):
    cve = cve_entry.get('cve', {})
 
    base = {
        'cve_id': cve.get('id'),
        'cve_sourceIdentifier': cve.get('sourceIdentifier'),
        'cve_published': cve.get('published'),
        'cve_lastModified': cve.get('lastModified'),
        'cve_vulnStatus': cve.get('vulnStatus'),
        'cve_cveTags': '|'.join(str(tag) for tag in cve.get('cveTags', [])) if cve.get('cveTags') else None,
    }
 
    descriptions = [{
        'cve_descriptions_lang': d.get('lang'),
        'cve_descriptions_value': d.get('value'),
    } for d in cve.get('descriptions', [])]
 
    metrics = []
    for metric in cve.get('metrics', {}).get('cvssMetricV2', []):
        m = {
            'cve_cvssMetricV2_source': metric.get('source'),
            'cve_cvssMetricV2_type': metric.get('type'),
        }
        cvss = metric.get('cvssData', {})
        m.update({
            'cve_cvssMetricV2_cvssData_version': cvss.get('version'),
            'cve_cvssMetricV2_cvssData_vectorString': cvss.get('vectorString'),
            'cve_cvssMetricV2_cvssData_baseScore': cvss.get('baseScore'),
            'cve_cvssMetricV2_cvssData_accessVector': cvss.get('accessVector'),
            'cve_cvssMetricV2_cvssData_accessComplexity': cvss.get('accessComplexity'),
            'cve_cvssMetricV2_cvssData_authentication': cvss.get('authentication'),
            'cve_cvssMetricV2_cvssData_confidentialityImpact': cvss.get('confidentialityImpact'),
            'cve_cvssMetricV2_cvssData_integrityImpact': cvss.get('integrityImpact'),
            'cve_cvssMetricV2_cvssData_availabilityImpact': cvss.get('availabilityImpact'),
            'cve_cvssMetricV2_baseSeverity': metric.get('baseSeverity'),
            'cve_cvssMetricV2_exploitabilityScore': metric.get('exploitabilityScore'),
            'cve_cvssMetricV2_impactScore': metric.get('impactScore'),
        })
        metrics.append(m)
 
    weaknesses = []
    for w in cve.get('weaknesses', []):
        for desc in w.get('description', []):
            weaknesses.append({
                'cve_weakness_source': w.get('source'),
                'cve_weakness_type': w.get('type'),
                'cve_weakness_lang': desc.get('lang'),
                'cve_weakness_value': desc.get('value')
            })
 
    cpes = []
    for config in cve.get('configurations', []):
        for node in config.get('nodes', []):
            for cpe in node.get('cpeMatch', []):
                cpes.append({
                    'cve_cpe_criteria': cpe.get('criteria'),
                    'cve_cpe_vulnerable': cpe.get('vulnerable'),
                    'cve_cpe_matchCriteriaId': cpe.get('matchCriteriaId')
                })
 
    references = [{'cve_reference_url': r.get('url'), 'cve_reference_source': r.get('source')} for r in cve.get('references', [])]
 
    # Set to [{}] if empty to ensure product still works
    descriptions = descriptions or [{}]
    metrics = metrics or [{}]
    weaknesses = weaknesses or [{}]
    cpes = cpes or [{}]
    references = references or [{}]
 
    rows = []
    for desc, metric, weak, cpe, ref in product(descriptions, metrics, weaknesses, cpes, references):
        row = {
            **base,
            **desc,
            **metric,
            **weak,
            **cpe,
            **ref
        }
        rows.append(row)
 
    return rows
 
 
def transform_data(data):
    all_rows = []
    for entry in data:
        all_rows.extend(flatten_cve(entry))
    return all_rows
 
 
def save_to_csv(data, filename='zoutput/try.csv'):
    if not data:
        print("No data to save.")
        return
 
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    keys = list(data[0].keys())
 
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)
    print(f"Data saved to {filename}")
 
 
def save_to_clickhouse(data, table_name='newtest.testnew'):
    if not data:
        print("No data to save.")
        return
 
    # Connect to ClickHouse
    client = clickhouse_connect.get_client(      
        host=Variable.get('CLICKHOUSE_HOST'),
        user=Variable.get('CLICKHOUSE_USER'),
        password=Variable.get('CLICKHOUSE_PASSWORD'),
        secure=True
    )
    print(f"Connected to ClickHouse at {Variable.get('CLICKHOUSE_HOST')}")
    # Check if the table exists
    try:
        table_exists = client.command(f"EXISTS {table_name}")
        if table_exists == 0:  # If the table does not exist
            # Create table
            client.command(f"""
CREATE TABLE {table_name}
(
    `cve_id` String,
    `cve_sourceIdentifier` String,
    `cve_published` DateTime64(9),
    `cve_lastModified` DateTime64(9),
    `cve_vulnStatus` String,
    `cve_cveTags` String,
    `cve_descriptions_lang` String,
    `cve_descriptions_value` String,
    `cve_cvssMetricV2_source` String,
    `cve_cvssMetricV2_type` String,
    `cve_cvssMetricV2_cvssData_version` Float64,
    `cve_cvssMetricV2_cvssData_vectorString` String,
    `cve_cvssMetricV2_cvssData_baseScore` Float64,
    `cve_cvssMetricV2_cvssData_accessVector` String,
    `cve_cvssMetricV2_cvssData_accessComplexity` String,
    `cve_cvssMetricV2_cvssData_authentication` String,
    `cve_cvssMetricV2_cvssData_confidentialityImpact` String,
    `cve_cvssMetricV2_cvssData_integrityImpact` String,
    `cve_cvssMetricV2_cvssData_availabilityImpact` String,
    `cve_cvssMetricV2_baseSeverity` String,
    `cve_cvssMetricV2_exploitabilityScore` Float64,
    `cve_cvssMetricV2_impactScore` Float64,
    `cve_weakness_source` String,
    `cve_weakness_type` String,
    `cve_weakness_lang` String,
    `cve_weakness_value` String,
    `cve_cpe_criteria` String,
    `cve_cpe_vulnerable` String,
    `cve_cpe_matchCriteriaId` String,
    `cve_reference_url` String,
    `cve_reference_source` String
)
ENGINE = SharedReplacingMergeTree()
ORDER BY cve_id
SETTINGS index_granularity = 8192
            """)
            print(f"Table {table_name} created.")
    except Exception as e:
        print(f"Error checking or creating table: {e}")
        return
 
    # Validate and log the data structure
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        print("Error: Data is not in the expected format (list of dictionaries).")
        print(f"Data type: {type(data)}")
        if isinstance(data, list):
            print(f"First row type: {type(data[0]) if data else 'N/A'}")
        return
 
    # Ensure data is a list of dictionaries with valid values
    formatted_data = []
    for row in data:
        formatted_row = {}
        for key, value in row.items():
            if key == 'cve_cpe_vulnerable':
                formatted_row[key] = 1 if value is True else 0 if value is False else value
            elif key in ['cve_published', 'cve_lastModified']:
                try:
                    formatted_row[key] = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%f') if value else None
                except ValueError:
                    formatted_row[key] = None
            else:
                formatted_row[key] = value
 
        formatted_row = {key: (value if value is not None else '') for key, value in formatted_row.items()}  # Replace None with ''
        formatted_data.append(formatted_row)
 
    # Convert the data to a Pandas DataFrame
    df = pd.DataFrame(formatted_data)
 
    # Ensure datetime objects for DateTime columns
    for column in ['cve_published', 'cve_lastModified']:
        if column in df.columns:
            df[column] = pd.to_datetime(df[column], errors='coerce')
 
    # Iterate through all columns and convert numpy.float64 to float or string
    for col in df.columns:
        if df[col].dtype == np.float64:
            # Try converting to string first
            try:
                df[col] = df[col].astype(str)
            except ValueError:
                # If string conversion fails, convert to float
                df[col] = df[col].astype(float)
        elif df[col].dtype == 'object':
            # If the column is of type object, try converting to string
            try:
                df[col] = df[col].astype(str)
            except Exception:
                pass
 
    # Insert data into the table using insert_df
    try:
        client.insert_df(table_name, df)
        print(f"Data saved to ClickHouse table {table_name}")
    except Exception as e:
        print(f"Error inserting data into ClickHouse: {e}")
        traceback.print_exc()  # Print the full traceback
        print(f"Formatted data sample: {formatted_data[:1]}")  # Log a sample of the data
 
 
def main():
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    data = fetch_nvd_data(api_url)
    transformed_data = transform_data(data)
    # save_to_csv(transformed_data)  # Save to CSV
    save_to_clickhouse(transformed_data)  # Save to ClickHouse
 
 
if __name__ == "__main__":
    main()