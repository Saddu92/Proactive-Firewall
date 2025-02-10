import pandas as pd


df= pd.read_csv("packet_features.csv")

df= pd.DataFrame(df)

df['Source IP'].ffill(inplace=True)

df['Destination IP'].ffill(inplace=True)

df['Protocol'].ffill(inplace=True)

df['Source Port'].fillna(df['Source Port'].mean(),inplace= True)

df['Destination Port'].fillna(df['Source Port'].mean(),inplace= True)

df['Flow Bytes/sec'].fillna(df['Flow Bytes/sec'].mode()[0],inplace= True)

df['Flow Duration'].fillna(df['Flow Duration'].mean(),inplace= True)


from sklearn.preprocessing import LabelEncoder

le = LabelEncoder()
df["Flags"] = le.fit_transform(df["Flags"])

df['Flags'].fillna(df['Flags'].mean(),inplace= True)

df['Forward Packet Length Mean'].fillna(df['Forward Packet Length Mean'].mean(),inplace= True)
df['Backward Packet Length Mean'].fillna(df['Backward Packet Length Mean'].mean(),inplace= True)






df['Total Forward Packets'].fillna(df['Total Forward Packets'].mode()[0], inplace=True)
df['Total Backward Packets'].fillna(df['Total Backward Packets'].mode()[0], inplace=True)


test1_columns=["Destination Port","Protocol","Flow Duration","Total Forward Packets","Total Backward Packets","Forward Packet Length Mean","Backward Packet Length Mean","Flow Bytes/sec","Flags"]


df=df[test1_columns]

# Assuming 'df' is your dataframe with the selected columns
df.rename(columns={
    "Destination Port": "Dst Port",
    "Protocol": "Protocol",
    "Flow Duration": "Flow Duration",
    "Total Forward Packets": "Tot Fwd Pkts",
    "Total Backward Packets": "Tot Bwd Pkts",
    "Forward Packet Length Mean": "Fwd Pkt Len Mean",
    "Backward Packet Length Mean": "Bwd Pkt Len Mean",
    "Flow Bytes/sec": "Flow Byts/s",
    "Flags":"SYN Flag Cnt"
}, inplace=True)

# Select only the relevant columns (now with CICIDS2018 names)
df = df[["Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", 
         "Fwd Pkt Len Mean", "Bwd Pkt Len Mean", "Flow Byts/s","SYN Flag Cnt"]]






# df.drop(columns=["Source IP","Destination IP","Source Port","Packet Length"],inplace=True)

from sklearn.preprocessing import MinMaxScaler

# Initialize MinMaxScaler
scaler = MinMaxScaler()

# Fit and transform the 'Flow Bytes/sec' column
df['Flow Byts/s'] = scaler.fit_transform(df[['Flow Byts/s']])

from sklearn.preprocessing import MinMaxScaler

# Initialize MinMaxScaler
scaler = MinMaxScaler()

# Fit and transform the 'Flow Bytes/sec' column
df['Fwd Pkt Len Mean'] = scaler.fit_transform(df[['Fwd Pkt Len Mean']])

from sklearn.preprocessing import MinMaxScaler

# Initialize MinMaxScaler
scaler = MinMaxScaler()

# Fit and transform the 'Flow Bytes/sec' column
df['Tot Fwd Pkts'] = scaler.fit_transform(df[['Tot Fwd Pkts']])

from sklearn.preprocessing import MinMaxScaler

# Initialize MinMaxScaler
scaler = MinMaxScaler()

# Fit and transform the 'Flow Bytes/sec' column
df['Dst Port'] = scaler.fit_transform(df[['Dst Port']])

df.to_csv("test_features.csv", index=False)  



