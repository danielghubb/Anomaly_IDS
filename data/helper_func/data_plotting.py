import pandas as pd
import matplotlib.pyplot as plt
import os
import re

def data_plotting(file_name):
    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_name)
    df = pd.read_json(json_path, lines=True)
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plots")
    output_folder_nums = os.path.join(output_folder, "numerical")
    output_folder_cats = os.path.join(output_folder, "categorical")
    os.makedirs(output_folder, exist_ok=True)
    os.makedirs(output_folder_nums, exist_ok=True)
    os.makedirs(output_folder_cats, exist_ok=True)
    print("total number of columns:", len(df.columns))
    print("number of numeric columns:", len(df.select_dtypes(include='number').columns))
    numeric_cols = df.select_dtypes(include='number').columns
    for col in numeric_cols:
        plt.figure(figsize=(10, 5))
        df[col].dropna().plot(kind='hist', bins=50, edgecolor='black')
        plt.title(f'Distribution of {col}')
        plt.xlabel(col)
        plt.ylabel('Frequency')
        plt.tight_layout()
        plot_path = os.path.join(output_folder_nums, f"{col}.png")
        plt.savefig(plot_path)
        plt.close()

    non_numeric_cols = df.select_dtypes(exclude='number')
    for col in non_numeric_cols:
        value_counts = df[col].value_counts()
        if len(value_counts) == 0:
            continue

        plt.figure(figsize=(12, 6))
        value_counts.plot(kind='bar')
        plt.title(f'Top 20 Values for {col}')
        plt.xlabel(col)
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        safe_col = re.sub(r'[\\/*?:"<>|]', '_', col)
        plt.savefig(os.path.join(output_folder_cats, f"{safe_col}.png"))
        plt.close()

    print("\nAll plots saved successfully in:", output_folder)

if __name__ == "__main__":
    data_plotting("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX_train.json")
    data_plotting("Wednesday-28-02-2018_mapped_train.json")