import pandas as pd

csv_path = r"backend/datasets/UNSW_NB15_training-set.csv"
df = pd.read_csv(csv_path)

print(f"Shape: {df.shape}")
print(f"Columns ({len(df.columns)}): {df.columns.tolist()}")

# Check target
df['attack_cat'] = df['attack_cat'].astype(str).str.strip()
print("\nTarget 'attack_cat' distribution:")
print(df['attack_cat'].value_counts())

# Features to exclude from X
drop_cols = ['id', 'label', 'attack_cat']
feature_cols = [c for c in df.columns if c not in drop_cols]
print(f"\nFeature columns count: {len(feature_cols)}")

X_sample = df[feature_cols]
cat_cols = X_sample.select_dtypes(include=['object']).columns.tolist()
num_cols = X_sample.select_dtypes(include=['number']).columns.tolist()

print(f"Categorical features ({len(cat_cols)}): {cat_cols}")
for c in cat_cols:
    print(f"  - {c}: {df[c].nunique()} unique values -> {df[c].unique()[:10]}")

print(f"\nNumerical features ({len(num_cols)}): {num_cols}")
