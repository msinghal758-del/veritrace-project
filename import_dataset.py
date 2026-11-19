"""
VeriTrace - Official UNSW-NB15 Dataset Importer & Inspector
Downloads the official UNSW-NB15 training dataset, inspects it with Pandas,
and stores the real cybersecurity records into the SQLite database.
"""

import os
import sys
import time
import urllib.request
import sqlite3
import pandas as pd
import numpy as np

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
CSV_PATH = os.path.join(DATASETS_DIR, "UNSW_NB15_training-set.csv")
DB_PATH = os.path.join(BASE_DIR, "veritrace.db")

# Official UNSW-NB15 dataset URL (Hosted on Hugging Face open datasets)
DATASET_URL = "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/UNSW_NB15_training-set.csv"


def download_dataset():
    """Download the official UNSW-NB15 CSV if not already present."""
    os.makedirs(DATASETS_DIR, exist_ok=True)
    if os.path.exists(CSV_PATH) and os.path.getsize(CSV_PATH) > 1000000:
        print(f"[OK] UNSW-NB15 dataset already exists at:\n     {CSV_PATH} ({os.path.getsize(CSV_PATH):,} bytes)")
        return

    print(f"[1/4] Downloading official UNSW-NB15 dataset from:\n      {DATASET_URL}")
    print("      This may take 10-30 seconds depending on your connection...")

    def progress_bar(blocks_transferred, block_size, total_size):
        downloaded = blocks_transferred * block_size
        if total_size > 0:
            percent = min(100.0, (downloaded / total_size) * 100)
            mb = downloaded / (1024 * 1024)
            total_mb = total_size / (1024 * 1024)
            sys.stdout.write(f"\r      Progress: {percent:.1f}% ({mb:.1f} MB of {total_mb:.1f} MB)")
            sys.stdout.flush()

    urllib.request.urlretrieve(DATASET_URL, CSV_PATH, reporthook=progress_bar)
    print(f"\n[OK] Download complete! Saved to {CSV_PATH}")


def inspect_dataset():
    """Load the dataset with Pandas and inspect its structure, missing values, and attack categories."""
    print("\n[2/4] Reading and inspecting dataset with Pandas...")
    start_time = time.time()
    df = pd.read_csv(CSV_PATH)
    elapsed = time.time() - start_time
    print(f"      Loaded in {elapsed:.2f} seconds.")

    # 1. Total records and columns
    total_records, total_columns = df.shape
    print("\n" + "=" * 60)
    print("  OFFICIAL UNSW-NB15 DATASET INSPECTION REPORT")
    print("=" * 60)
    print(f"  Total Records (Rows)   : {total_records:,}")
    print(f"  Total Features (Cols)  : {total_columns}")

    # 2. Columns List
    print("\n  Features / Columns:")
    col_list = df.columns.tolist()
    for i in range(0, len(col_list), 5):
        print("    " + ", ".join(col_list[i : i + 5]))

    # 3. Missing values check
    missing_counts = df.isnull().sum()
    total_missing = missing_counts.sum()
    print(f"\n  Missing Values Check:")
    if total_missing == 0:
        print("    [None] Zero missing values detected across all columns. Clean dataset!")
    else:
        print(f"    Total Missing Values: {total_missing}")
        for col, count in missing_counts[missing_counts > 0].items():
            print(f"    - {col}: {count} missing")

    # 4. Attack categories distribution
    print("\n  Attack Categories (attack_cat):")
    # Clean whitespace in attack_cat if any
    df['attack_cat'] = df['attack_cat'].astype(str).str.strip()
    attack_counts = df['attack_cat'].value_counts()
    for cat, count in attack_counts.items():
        pct = (count / total_records) * 100
        print(f"    - {cat:<18}: {count:>8,} records ({pct:>5.1f}%)")

    # 5. Normal vs Attack distribution (binary label)
    print("\n  Binary Traffic Labels (0 = Normal, 1 = Attack):")
    label_counts = df['label'].value_counts()
    for lbl, count in label_counts.items():
        name = "Attack" if lbl == 1 else "Normal"
        pct = (count / total_records) * 100
        print(f"    - {name:<18} (label={lbl}): {count:>8,} records ({pct:>5.1f}%)")

    print("=" * 60)
    return df


def store_in_sqlite(df: pd.DataFrame):
    """Store the imported dataset and its calculated statistics into SQLite."""
    print("\n[3/4] Storing dataset in SQLite database (veritrace.db)...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Clean whitespace in string columns
    df['attack_cat'] = df['attack_cat'].astype(str).str.strip()
    df['proto'] = df['proto'].astype(str).str.strip()
    df['service'] = df['service'].astype(str).str.strip()
    df['state'] = df['state'].astype(str).str.strip()

    # Store all 175,341 real records in 'unsw_dataset'
    print(f"      Writing all {len(df):,} actual records to 'unsw_dataset' table...")
    df.to_sql("unsw_dataset", conn, if_exists="replace", index=False, chunksize=10000)
    print(f"      [OK] Stored all {len(df):,} actual records into table 'unsw_dataset'.")

    # Create index on attack_cat, proto, and label for lightning fast API queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_unsw_cat ON unsw_dataset(attack_cat);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_unsw_lbl ON unsw_dataset(label);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_unsw_proto ON unsw_dataset(proto);")

    # Store high-level dataset statistics in 'dataset_metadata' table
    print("\n[4/4] Generating and storing metadata statistics...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dataset_metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)

    # Prepare stats summary as JSON-ready structures
    attack_dist = df['attack_cat'].value_counts().to_dict()
    proto_dist = df['proto'].value_counts().head(10).to_dict()
    service_dist = df['service'].value_counts().head(10).to_dict()

    import json
    metadata = {
        "dataset_name": "UNSW-NB15 Network Intrusion Dataset",
        "source": "Australian Centre for Cyber Security (ACCS), UNSW Canberra",
        "total_records": int(len(df)),
        "total_features": int(len(df.columns)),
        "columns": df.columns.tolist(),
        "attack_categories": attack_dist,
        "top_protocols": proto_dist,
        "top_services": service_dist,
        "normal_count": int(df['label'].value_counts().get(0, 0)),
        "attack_count": int(df['label'].value_counts().get(1, 0)),
        "imported_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }

    for k, v in metadata.items():
        val_str = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        cursor.execute("INSERT OR REPLACE INTO dataset_metadata (key, value) VALUES (?, ?);", (k, val_str))

    conn.commit()
    conn.close()
    print("      [OK] Metadata and statistics saved to SQLite successfully!")
    print(f"\n[DONE] SQLite Database Ready: {DB_PATH}")


if __name__ == "__main__":
    download_dataset()
    dataframe = inspect_dataset()
    store_in_sqlite(dataframe)
