import json
import random
import pandas as pd

def split_json(input_file, train_ratio, test_ratio, val_ratio, seed=42):
    data = pd.read_json(input_file, lines=True)
    print(f"Total samples: {len(data)}")
    data = data.drop_duplicates()
    print(f"Samples after removing duplicates: {len(data)}")
    print(data.columns)
    data = data.to_dict(orient="records")

    # Shuffle data ranndomly
    random.seed(seed)
    random.shuffle(data)
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

    # Saving
    base_name = input_file.rsplit('.', 1)[0]
    train_df.to_json(f"{base_name}_train.json", orient="records", lines=True)
    test_df.to_json(f"{base_name}_test.json", orient="records", lines=True)
    val_df.to_json(f"{base_name}_val.json", orient="records", lines=True)

    print(f"Split complete: {len(train_data)} train, {len(test_data)} test, {len(val_data)} val samples.")

if __name__ == "__main__":
    # split_json(
    #     input_file="data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.json",
    #     train_ratio=0.7,
    #     test_ratio=0.2,
    #     val_ratio=0.1,)
    # split_json(
    #     input_file="data/Monday-WorkingHours.pcap_ISCX.json",
    #     train_ratio=0.8,
    #     test_ratio=0.2,
    #     val_ratio=0,)
    split_json(
        input_file="data/Wednesday-28-02-2018_mapped.json",
        train_ratio=0.7,
        test_ratio=0.2,
        val_ratio=0.1,)

