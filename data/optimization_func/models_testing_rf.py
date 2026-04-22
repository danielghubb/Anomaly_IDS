import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt

filename = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX"
train_df = pd.read_json(filename + "_train.json",lines=True)
test_df  = pd.read_json(filename + "_test.json",lines=True)
val_df   = pd.read_json(filename + "_val.json",lines=True)

target_column = "Label"

# Split features and labels
X_train = train_df.drop(columns=[target_column])
print(X_train.head())
y_train = train_df[target_column]
print(y_train.head())
X_test = test_df.drop(columns=[target_column])
print(X_test.head())
y_test = test_df[target_column]
print(y_test.head())
X_val = val_df.drop(columns=[target_column])
y_val = val_df[target_column]

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

#Testing reduced features
top50_indices = indices[:50]
top50_features = feature_names[top50_indices]

print("Top-50 most important features being removed:")
print(top50_features)

# Drop them from sets
X_train_reduced = X_train.drop(columns=top50_features)
print(X_train_reduced.head())
X_test_reduced  = X_test.drop(columns=top50_features)
print(X_test_reduced.head())
X_val_reduced   = X_val.drop(columns=top50_features)
print(X_val_reduced.head())

print("\nShapes after feature removal:")
print("Train:", X_train_reduced.shape)
print("Test :", X_test_reduced.shape)
print("Val  :", X_val_reduced.shape)

# Retrain on reduced features
rf_reduced = RandomForestClassifier(
    n_estimators=200,
    max_depth=2,
    min_samples_leaf=1,
    random_state=42,
    n_jobs=-1
)

rf_reduced.fit(X_train_reduced, y_train)
y_pred_test_reduced = rf_reduced.predict(X_test_reduced)
y_pred_val_reduced  = rf_reduced.predict(X_val_reduced)

print("\nTest Performance (Top-50 features removed)")
print(classification_report(y_test, y_pred_test_reduced))
print("Val Performance (Top-50 features removed)")
print(classification_report(y_val, y_pred_val_reduced))

importances = rf_reduced.feature_importances_
feature_names = X_train_reduced.columns

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