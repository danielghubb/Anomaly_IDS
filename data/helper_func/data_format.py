import pandas as pd
import os
import re
import json

def csv_to_json_currentdir():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    input_folder = current_dir
    output_folder = current_dir
    os.makedirs(output_folder, exist_ok=True)
    for filename in os.listdir(input_folder):
        if filename.endswith(".csv"):
            csv_path = os.path.join(input_folder, filename)
            json_path = os.path.join(output_folder, filename.replace(".csv", ".json"))
            df = pd.read_csv(csv_path, low_memory=False)
            df.columns = df.columns.str.replace(r'[\\/*?:"<>| ]', '', regex=True)
            df.to_json(json_path, orient="records", lines=True)
