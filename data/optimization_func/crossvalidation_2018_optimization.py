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


def objective(trial):
    filename = "data/Wednesday-28-02-2018_mapped"
    train_ratio = 0.7
    test_ratio = 0.2
    val_ratio = 0.1
    data = pd.read_json(filename + ".json", lines=True)
    data = data.drop_duplicates()
    data = data.to_dict(orient="records")

    # Shuffle data ranndomly
    random.seed(random.randint(0, 10000))
    random.shuffle(data)

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

    n_estimators = trial.suggest_int("n_estimators", 50, 500)
    max_depth = trial.suggest_int("max_depth", 2, 20)
    min_samples_leaf = trial.suggest_int("min_samples_leaf", 1, 10)

    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_leaf=min_samples_leaf,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    y_pred_new_trial = rf.predict(X_new)
    score = f1_score(y_new_testing, y_pred_new_trial, pos_label="Infiltration - NMAP Portscan")
    return score

if __name__ == "__main__":
    study = optuna.create_study(
        study_name="rf_portscan_study_training_2018_crossvalidation",
        storage="sqlite:///optuna_trials.db",
        direction="maximize",
        load_if_exists=True
    )
    study.optimize(objective, n_trials=500)
