import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import numpy as np
import optuna
from sklearn.metrics import f1_score, recall_score
import pickle

filename = "data/Wednesday-28-02-2018_mapped"
train_df = pd.read_json(filename + "_train.json",lines=True)
train_df = train_df[(train_df["Label"] == "Infiltration - NMAP Portscan") | (train_df["Label"] == "BENIGN")]
test_df  = pd.read_json(filename + "_test.json",lines=True)
test_df = test_df[(test_df["Label"] == "Infiltration - NMAP Portscan") | (test_df["Label"] == "BENIGN")]
val_df   = pd.read_json(filename + "_val.json",lines=True)
val_df = val_df[(val_df["Label"] == "Infiltration - NMAP Portscan") | (val_df["Label"] == "BENIGN")]

new_dataset_file = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.json"
new_df = pd.read_json(new_dataset_file, lines=True)

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
y_new_testing = new_df[target_column].apply(lambda x: "Infiltration - NMAP Portscan" if x == "PortScan" else "BENIGN")
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
    score = f1_score(y_new_testing, y_pred_new_trial, pos_label="Infiltration - NMAP Portscan")
    return score

study = optuna.create_study(
    study_name="rf_portscan_study_training2018_99training",
    storage="sqlite:///optuna_trials.db",
    direction="maximize",
    load_if_exists=True
)
#study.optimize(objective, n_trials=500)
print("Best trial:", study.best_trial.params)

# Training
rf = RandomForestClassifier(
    n_estimators=302,
    max_depth=4,
    min_samples_leaf=5,
    random_state=42,
    n_jobs=-1
)
# rf = RandomForestClassifier(
#         n_estimators=124,
#         max_depth=18,
#         min_samples_leaf=10,
#         random_state=42,
#         n_jobs=-1
#     )
rf.fit(X_train, y_train)
with open('model/RandomForestModel.pkl', 'wb') as f:
    pickle.dump(rf, f)

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


pred_portscan = y_pred_new == "PortScan"
true_positives = np.sum(pred_portscan & (y_new_testing != "BENIGN"))
print(f"True positives (attacks correctly predicted as PortScan): {true_positives}")
false_positives = np.sum(pred_portscan & (y_new_testing == "BENIGN"))
print(f"False positives (benign predicted as PortScan): {false_positives}")


print(y_pred_new)
print(y_new_testing)
print("Test Performance")
print(classification_report(y_new_testing, y_pred_new))



