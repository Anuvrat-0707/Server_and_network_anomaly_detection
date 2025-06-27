# data_loader.py
import pandas as pd
from pathlib import Path
import zipfile
from sklearn.model_selection import train_test_split

def extract_and_process_dataset(zip_path, test_size=0.2, random_state=42):
    extracted_path = Path(zip_path).with_suffix("")

    # Extract ZIP archive
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extracted_path)

    txt_files = list(extracted_path.glob("*.txt"))

    datasets = {}

    for file in txt_files:
        df = pd.read_csv(file, header=None, delim_whitespace=False)

        # Automatically name columns
        num_features = df.shape[1] - 1
        df.columns = [f"feature_{i}" for i in range(num_features)] + ["label"]

        key = file.stem.lower()
        datasets[key] = df

    # If only one dataset, split it
    if len(datasets) == 1:
        only_key = next(iter(datasets))
        full_df = datasets[only_key]

        train_df, test_df = train_test_split(full_df, test_size=test_size, random_state=random_state, stratify=full_df["label"])
        datasets["train"] = train_df.reset_index(drop=True)
        datasets["test"] = test_df.reset_index(drop=True)
        del datasets[only_key]

    return datasets
