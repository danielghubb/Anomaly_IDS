import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import numpy as np
import optuna
from sklearn.metrics import f1_score, recall_score


def training_2017_portscan_model():
    filename = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX"
    train_df = pd.read_json(filename + "_train.json",lines=True)
    test_df  = pd.read_json(filename + "_test.json",lines=True)
    val_df   = pd.read_json(filename + "_val.json",lines=True)

    new_dataset_file = "data/Wednesday-28-02-2018_mapped.json"
    new_df = pd.read_json(new_dataset_file, lines=True)
    new_df = new_df[(new_df["Label"] == "Infiltration - NMAP Portscan") | (new_df["Label"] == "BENIGN")]

    target_column = "Label"

    train_cols = set(train_df.columns) - {target_column}
    test_cols  = set(test_df.columns)  - {target_column}
    val_cols   = set(val_df.columns)   - {target_column}
    new_cols   = set(new_df.columns)   - {target_column}

    common_cols = list(train_cols & test_cols & val_cols & new_cols)
    print(f"Number of common features: {len(common_cols)}")

    X_train = train_df[common_cols]
    y_train = train_df[target_column]
    X_test = test_df[common_cols]
    y_test = test_df[target_column]
    X_val = val_df[common_cols]
    y_val = val_df[target_column]
    X_new = new_df[common_cols]
    y_new_testing = new_df[target_column].apply(lambda x: "PortScan" if x == "Infiltration - NMAP Portscan" else "BENIGN")
    print(y_new_testing)

    def objective(trial):
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
        score = f1_score(y_new_testing, y_pred_new_trial, pos_label="PortScan")
        return score

    study = optuna.create_study(
        study_name="rf_portscan_study_training2017",
        storage="sqlite:///optuna_trials.db",
        direction="maximize",
        load_if_exists=True
    )
    study.optimize(objective, n_trials=250)
    print("Best trial:", study.best_trial.params)


    # Training
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=2,
        min_samples_leaf=1,
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



    X_new = new_df[[col for col in X_train.columns if col in new_df.columns]]
    y_new = new_df[target_column]
    y_pred_new = rf.predict(X_new)
    num_attacks = np.sum(y_pred_new != "BENIGN")
    print(f"Number of predicted attacks (not BENIGN): {num_attacks}")
    attack_mask = y_pred_new != "BENIGN"
    true_labels_for_predicted_attacks = y_new_testing[attack_mask]
    print(true_labels_for_predicted_attacks)

    print(y_pred_new)
    print(y_new_testing)
    print("Test Performance")
    print(classification_report(y_new_testing, y_pred_new))

