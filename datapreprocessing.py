import pandas as pd

# Load the CSV data
file_path = 'packet_features.csv'  # Update with your file path
data = pd.read_csv(file_path)

# Display initial data shape
print(f"Initial data shape: {data.shape}")

# Remove rows with missing critical fields (e.g., Source IP, Destination IP)
data = data.dropna(subset=["Source IP", "Destination IP"], how="any")

# Fill missing values in non-critical fields with defaults
data["Protocol"] = data["Protocol"].fillna("Unknown")
data["Flags"] = data["Flags"].fillna("None")
data["Source Port"] = data["Source Port"].fillna(0).astype(int)
data["Destination Port"] = data["Destination Port"].fillna(0).astype(int)
data["Packet Length"] = data["Packet Length"].fillna(0).astype(int)

# Normalize Protocol (e.g., ensure consistent capitalization)
data["Protocol"] = data["Protocol"].apply(lambda x: str(x).upper())

# Deduplicate data
data = data.drop_duplicates()

# Reorder columns (optional)
columns_order = ["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Flags", "Packet Length"]
data = data[columns_order]

# Save cleaned data to a new CSV
cleaned_file_path = "cleaned_normalized_data.csv"
data.to_csv(cleaned_file_path, index=False)

# Display cleaned data shape
print(f"Cleaned data shape: {data.shape}")
print(f"Cleaned data saved to {cleaned_file_path}")
