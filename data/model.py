import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import numpy as np
import optuna
from sklearn.metrics import f1_score, recall_score
import pickle

# Personal functions
from helper_func.data_split import split_json

def run_model():
    filename = "data/Wednesday-28-02-2018_mapped"
    train_df = pd.read_json(filename + ".json",lines=True)
    train_df = train_df[(train_df["Label"] == "Infiltration - NMAP Portscan") | (train_df["Label"] == "BENIGN")]

    target_column = "Label"

    train_cols = list(set(train_df.columns) - {target_column})

    X_train = train_df[train_cols]
    y_train = train_df[target_column]


    # Training

    # Old best params
    # rf = RandomForestClassifier(
    #     n_estimators=302,
    #     max_depth=4,
    #     min_samples_leaf=5,
    #     random_state=42,
    #     n_jobs=-1
    # )

    # New best params from optuna
    rf = RandomForestClassifier(
            n_estimators=124,
            max_depth=18,
            min_samples_leaf=10,
            random_state=42,
            n_jobs=-1
        )

    rf.fit(X_train, y_train)
    with open('model/RandomForestModel_validation.pkl', 'wb') as f:
        pickle.dump(rf, f)


def test_model():
    filename = "data/Wednesday-28-02-2018_mapped"
    split_json(
            input_file= str(filename) + ".json",
            train_ratio=0.7,
            test_ratio=0.2,
            val_ratio=0.1,)
    train_df = pd.read_json(filename + "_train.json",lines=True)
    train_df = train_df[(train_df["Label"] == "Infiltration - NMAP Portscan") | (train_df["Label"] == "BENIGN")]
    test_df  = pd.read_json(filename + "_test.json",lines=True)
    test_df = test_df[(test_df["Label"] == "Infiltration - NMAP Portscan") | (test_df["Label"] == "BENIGN")]
    val_df   = pd.read_json(filename + "_val.json",lines=True)
    val_df = val_df[(val_df["Label"] == "Infiltration - NMAP Portscan") | (val_df["Label"] == "BENIGN")]


    target_column = "Label"
    train_cols = list(set(train_df.columns) - {target_column})
    test_cols  = list(set(test_df.columns)  - {target_column})
    val_cols   = list(set(val_df.columns)   - {target_column})
    X_train = train_df[train_cols]
    y_train = train_df[target_column]
    X_test = test_df[test_cols]
    y_test = test_df[target_column]
    X_val = val_df[val_cols]
    y_val = val_df[target_column]


    # Training

    # Old best params
    # rf = RandomForestClassifier(
    #     n_estimators=302,
    #     max_depth=4,
    #     min_samples_leaf=5,
    #     random_state=42,
    #     n_jobs=-1
    # )

    # New best params from optuna
    rf = RandomForestClassifier(
            n_estimators=124,
            max_depth=18,
            min_samples_leaf=10,
            random_state=42,
            n_jobs=-1
        )

    rf.fit(X_train, y_train)

    # Eval
    y_pred_test = rf.predict(X_test)
    y_pred_val = rf.predict(X_val)


    print("Test Performance")
    print(classification_report(y_test, y_pred_test))
    print("Val Performance")
    print(classification_report(y_val, y_pred_val))


    importances = rf.feature_importances_
    feature_names = X_train.columns

    # Sort features by importance
    indices = importances.argsort()[::-1]

    plt.figure(figsize=(10,6))
    plt.title("Feature Importances")
    plt.bar(range(len(importances)), importances[indices], align="center")
    plt.xticks(range(len(importances)), feature_names[indices], rotation=90)
    plt.tight_layout()
    plt.show()

    # Check for duplicates between train and test
    duplicates = pd.merge(train_df, test_df, how='inner')
    print(f"Number of overlapping rows between train and test: {len(duplicates)}")

if __name__ == "__main__":
    # comment out one if you don't want to run both
    test_model()
    run_model()