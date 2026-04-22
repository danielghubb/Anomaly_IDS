from datetime import datetime
from time import ctime
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import numpy as np
import optuna
from sklearn.metrics import f1_score, recall_score, precision_score
import random

def run_rf_model(data):
    train_ratio = 0.99
    test_ratio = 0.01
    val_ratio = 0
    # filename = "data/Wednesday-28-02-2018_mapped"
    # train_ratio = 0.7
    # test_ratio = 0.2
    # val_ratio = 0.1
    # data = pd.read_json(filename + ".json", lines=True)
    # data = data.drop_duplicates()
    # data = data.to_dict(orient="records")

    # # Shuffle data ranndomly
    # random.seed(random.randint(0, 10000))
    # random.shuffle(data)
    #data = data.sample(frac=1, random_state=seed).reset_index(drop=True)

    total = len(data)
    train_end = int(total * train_ratio)
    test_end = train_end + int(total * test_ratio)
    train_data = data[:train_end]
    test_data = data[train_end:test_end]
    val_data = data[test_end:]

    # Convert to pandas Dataframe
    train_df = pd.DataFrame(train_data)
    test_df = pd.DataFrame(test_data)
    val_df = pd.DataFrame(val_data)

    train_df = train_df[(train_df["Label"] == "Infiltration - NMAP Portscan") | (train_df["Label"] == "BENIGN")]
    test_df = test_df[(test_df["Label"] == "Infiltration - NMAP Portscan") | (test_df["Label"] == "BENIGN")]
    val_df = val_df[(val_df["Label"] == "Infiltration - NMAP Portscan") | (val_df["Label"] == "BENIGN")]

    new_dataset_file = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.json"
    new_df = pd.read_json(new_dataset_file, lines=True)

    target_column = "Label"

    train_cols = set(train_df.columns) - {target_column}
    test_cols  = set(test_df.columns)  - {target_column}
    val_cols   = set(val_df.columns)   - {target_column}
    new_cols   = set(new_df.columns)   - {target_column}

    common_cols = list(train_cols & test_cols & val_cols & new_cols)
    #print(f"Number of common features: {len(common_cols)}")

    X_train = train_df[common_cols]
    y_train = train_df[target_column]
    X_new = new_df[common_cols]
    y_new_testing = new_df[target_column].apply(lambda x: "Infiltration - NMAP Portscan" if x == "PortScan" else "BENIGN")

    # Training
    rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=18,
        min_samples_leaf=10,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    X_new = new_df[[col for col in X_train.columns if col in new_df.columns]]
    y_pred_new = rf.predict(X_new)
    return f1_score(y_new_testing, y_pred_new, pos_label="Infiltration - NMAP Portscan"), recall_score(y_new_testing, y_pred_new, pos_label="Infiltration - NMAP Portscan"), precision_score(y_new_testing, y_pred_new, pos_label="Infiltration - NMAP Portscan")


if __name__ == "__main__":
    mean_f1 = 0
    mean_recall = 0
    mean_precision = 0
    max_f1 = 0
    max_recall = 0
    max_precision = 0
    min_f1 = 1
    min_recall = 1
    min_precision = 1
    filename = "data/Wednesday-28-02-2018_mapped"
    train_ratio = 0.7
    test_ratio = 0.2
    val_ratio = 0.1
    data = pd.read_json(filename + ".json", lines=True)
    data = data.drop_duplicates()
    data = data.to_dict(orient="records")
    for i in range(100):
        print(f"Run {i+1}/100 at {ctime()}")
        # Shuffle data ranndomly
        random.seed(random.randint(0, 10000))
        random.shuffle(data)
        f1, recall, precision = run_rf_model(data)
        mean_f1 += f1
        mean_recall += recall
        mean_precision += precision
        if f1 > max_f1:
            max_f1 = f1
        if recall > max_recall:
            max_recall = recall
        if precision > max_precision:
            max_precision = precision
        if f1 < min_f1:
            min_f1 = f1
        if recall < min_recall:
            min_recall = recall
        if precision < min_precision:
            min_precision = precision

    print(f"Mean F1-score over 100 runs: {mean_f1 / 100}")
    print(f"Max F1-score over 100 runs: {max_f1}")
    print(f"Min F1-score over 100 runs: {min_f1}")
    print(f"Mean Recall over 100 runs: {mean_recall / 100}")
    print(f"Max Recall over 100 runs: {max_recall}")
    print(f"Min Recall over 100 runs: {min_recall}")
    print(f"Mean Precision over 100 runs: {mean_precision / 100}")
    print(f"Max Precision over 100 runs: {max_precision}")
    print(f"Min Precision over 100 runs: {min_precision}")
