import pandas as pd
from sklearn.svm import SVC
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder, StandardScaler
import matplotlib.pyplot as plt

filename = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX"
train_df = pd.read_json(filename + "_train.json", lines=True)
test_df  = pd.read_json(filename + "_test.json", lines=True)
val_df   = pd.read_json(filename + "_val.json", lines=True)
target_column = "Label"

# SVM requires no NaN values
train_df = train_df.fillna(0)
test_df = test_df.fillna(0)
val_df = val_df.fillna(0)


X_train = train_df.drop(columns=[target_column])
y_train = train_df[target_column]
X_test = test_df.drop(columns=[target_column])
y_test = test_df[target_column]
X_val = val_df.drop(columns=[target_column])
y_val = val_df[target_column]


scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)
X_val   = scaler.transform(X_val)


svm = SVC(
    C=1.0,
    kernel='rbf',
    gamma='scale'
)

svm.fit(X_train, y_train)
y_pred_test = svm.predict(X_test)
y_pred_val  = svm.predict(X_val)

print("Test Performance")
print(classification_report(y_test, y_pred_test))
print("Val Performance")
print(classification_report(y_val, y_pred_val))


duplicates = pd.merge(train_df, test_df, how='inner')
print(f"Number of overlapping rows between train and test: {len(duplicates)}")


