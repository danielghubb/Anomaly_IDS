import pandas as pd
import json

# Target features
target_features = [
    'DestinationPort', 'FlowDuration', 'TotalFwdPackets', 'TotalBackwardPackets',
    'TotalLengthofFwdPackets', 'TotalLengthofBwdPackets', 'FwdPacketLengthMax',
    'FwdPacketLengthMin', 'FwdPacketLengthMean', 'FwdPacketLengthStd',
    'BwdPacketLengthMax', 'BwdPacketLengthMin', 'BwdPacketLengthMean',
    'BwdPacketLengthStd', 'FlowBytess', 'FlowPacketss', 'FlowIATMean',
    'FlowIATStd', 'FlowIATMax', 'FlowIATMin', 'FwdIATTotal', 'FwdIATMean',
    'FwdIATStd', 'FwdIATMax', 'FwdIATMin', 'BwdIATTotal', 'BwdIATMean',
    'BwdIATStd', 'BwdIATMax', 'BwdIATMin', 'FwdPSHFlags', 'BwdPSHFlags',
    'FwdURGFlags', 'BwdURGFlags', 'FwdHeaderLength', 'BwdHeaderLength',
    'FwdPacketss', 'BwdPacketss', 'MinPacketLength', 'MaxPacketLength',
    'PacketLengthMean', 'PacketLengthStd', 'PacketLengthVariance',
    'FINFlagCount', 'SYNFlagCount', 'RSTFlagCount', 'PSHFlagCount',
    'ACKFlagCount', 'URGFlagCount', 'CWEFlagCount', 'ECEFlagCount',
    'DownUpRatio', 'AveragePacketSize', 'AvgFwdSegmentSize', 'AvgBwdSegmentSize',
    'FwdHeaderLength.1', 'FwdAvgBytesBulk', 'FwdAvgPacketsBulk', 'FwdAvgBulkRate',
    'BwdAvgBytesBulk', 'BwdAvgPacketsBulk', 'BwdAvgBulkRate', 'SubflowFwdPackets',
    'SubflowFwdBytes', 'SubflowBwdPackets', 'SubflowBwdBytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'ActiveMean', 'ActiveStd', 'ActiveMax', 'ActiveMin',
    'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin', 'Label'
]

# Mapping dictionary
mapping = {
    "DstPort": "DestinationPort",
    "FlowDuration": "FlowDuration",
    "TotalFwdPacket": "TotalFwdPackets",
    "TotalBwdpackets": "TotalBackwardPackets",
    "TotalLengthofFwdPacket": "TotalLengthofFwdPackets",
    "TotalLengthofBwdPacket": "TotalLengthofBwdPackets",
    "FwdPacketLengthMax": "FwdPacketLengthMax",
    "FwdPacketLengthMin": "FwdPacketLengthMin",
    "FwdPacketLengthMean": "FwdPacketLengthMean",
    "FwdPacketLengthStd": "FwdPacketLengthStd",
    "BwdPacketLengthMax": "BwdPacketLengthMax",
    "BwdPacketLengthMin": "BwdPacketLengthMin",
    "BwdPacketLengthMean": "BwdPacketLengthMean",
    "BwdPacketLengthStd": "BwdPacketLengthStd",
    "FlowBytess": "FlowBytess",
    "FlowPacketss": "FlowPacketss",
    "FlowIATMean": "FlowIATMean",
    "FlowIATStd": "FlowIATStd",
    "FlowIATMax": "FlowIATMax",
    "FlowIATMin": "FlowIATMin",
    "FwdIATTotal": "FwdIATTotal",
    "FwdIATMean": "FwdIATMean",
    "FwdIATStd": "FwdIATStd",
    "FwdIATMax": "FwdIATMax",
    "FwdIATMin": "FwdIATMin",
    "BwdIATTotal": "BwdIATTotal",
    "BwdIATMean": "BwdIATMean",
    "BwdIATStd": "BwdIATStd",
    "BwdIATMax": "BwdIATMax",
    "BwdIATMin": "BwdIATMin",
    "FwdPSHFlags": "FwdPSHFlags",
    "BwdPSHFlags": "BwdPSHFlags",
    "FwdURGFlags": "FwdURGFlags",
    "BwdURGFlags": "BwdURGFlags",
    "FwdHeaderLength": "FwdHeaderLength",
    "BwdHeaderLength": "BwdHeaderLength",
    "FwdPacketss": "FwdPacketss",
    "BwdPacketss": "BwdPacketss",
    "PacketLengthMin": "MinPacketLength",
    "PacketLengthMax": "MaxPacketLength",
    "PacketLengthMean": "PacketLengthMean",
    "PacketLengthStd": "PacketLengthStd",
    "PacketLengthVariance": "PacketLengthVariance",
    "FINFlagCount": "FINFlagCount",
    "SYNFlagCount": "SYNFlagCount",
    "RSTFlagCount": "RSTFlagCount",
    "PSHFlagCount": "PSHFlagCount",
    "ACKFlagCount": "ACKFlagCount",
    "URGFlagCount": "URGFlagCount",
    "CWRFlagCount": "CWEFlagCount",
    "ECEFlagCount": "ECEFlagCount",
    "DownUpRatio": "DownUpRatio",
    "AveragePacketSize": "AveragePacketSize",
    "FwdSegmentSizeAvg": "AvgFwdSegmentSize",
    "BwdSegmentSizeAvg": "AvgBwdSegmentSize",
    "FwdBytesBulkAvg": "FwdAvgBytesBulk",
    "FwdPacketBulkAvg": "FwdAvgPacketsBulk",
    "FwdBulkRateAvg": "FwdAvgBulkRate",
    "BwdBytesBulkAvg": "BwdAvgBytesBulk",
    "BwdPacketBulkAvg": "BwdAvgPacketsBulk",
    "BwdBulkRateAvg": "BwdAvgBulkRate",
    "SubflowFwdPackets": "SubflowFwdPackets",
    "SubflowFwdBytes": "SubflowFwdBytes",
    "SubflowBwdPackets": "SubflowBwdPackets",
    "SubflowBwdBytes": "SubflowBwdBytes",
    "FWDInitWinBytes": "Init_Win_bytes_forward",
    "BwdInitWinBytes": "Init_Win_bytes_backward",
    "FwdActDataPkts": "act_data_pkt_fwd",
    "FwdSegSizeMin": "min_seg_size_forward",
    "ActiveMean": "ActiveMean",
    "ActiveStd": "ActiveStd",
    "ActiveMax": "ActiveMax",
    "ActiveMin": "ActiveMin",
    "IdleMean": "IdleMean",
    "IdleStd": "IdleStd",
    "IdleMax": "IdleMax",
    "IdleMin": "IdleMin",
    "Label": "Label"
}

def map_and_filter_columns(df, mapping, target_features):
    df = df.rename(columns=mapping)
    df = df[[col for col in target_features if col in df.columns]]
    df = df.reindex(columns=[col for col in target_features if col in df.columns])
    return df

def mapping_dataset(input_file="data/Wednesday-28-02-2018.json", output_file="data/Wednesday-28-02-2018_mapped.json", chunksize=100000, first_chunks=0):
    with pd.read_json(input_file, lines=True, chunksize=chunksize) as reader, open(output_file, "w") as outfile:
        for i, chunk in enumerate(reader):
            chunk_mapped = map_and_filter_columns(chunk, mapping, target_features)
            if first_chunks > 2:
                chunk_attacks = chunk_mapped[chunk_mapped['Label'] != 'BENIGN']
                for row in chunk_attacks.to_dict(orient="records"):
                    outfile.write(json.dumps(row) + "\n")
                print(f"Chunk {i+1} processed, {len(chunk_attacks)} rows written.")
            else:
                chunk_attacks = chunk_mapped[chunk_mapped['Label'] == 'BENIGN']
                for row in chunk_attacks.to_dict(orient="records"):
                    outfile.write(json.dumps(row) + "\n")
                print(f"Chunk {i+1} processed, {len(chunk_attacks)} rows written.")
            first_chunks += 1

