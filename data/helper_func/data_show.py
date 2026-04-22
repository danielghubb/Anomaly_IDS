import pandas as pd

def data_show(file_name):
    df_iter = pd.read_json(file_name,
                        lines=True,
                        chunksize=50)

    df = next(df_iter)
    print(df)
    cols = list(df.columns)
    print(cols)

if __name__ == "__main__":
    data_show("data/Wednesday-28-02-2018.json")
    data_show("data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.json")
