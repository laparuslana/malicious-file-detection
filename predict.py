import joblib
import pandas as pd
import os
import modify
import hash_check


model_dir = "model"

rf_model = joblib.load(os.path.join(model_dir, 'file_classification_model.pkl'))
label_encoder = pd.read_pickle(os.path.join(model_dir, 'label_encoder.pkl'))
scaler_mean = pd.read_pickle(os.path.join(model_dir, 'scaler_mean.pkl'))
scaler_scale = pd.read_pickle(os.path.join(model_dir, 'scaler_scale.pkl'))


def extract_features(file_path):
    try:
        size = os.path.getsize(file_path)

        sha256_hash = modify.calculate_hash(file_path, "sha256")

        entropy = modify.calculate_entropy(file_path)

        file_extension = os.path.splitext(file_path)[1].lower()

        return {
            'Size (bytes)': size,
            'Entropy': entropy,
            'Extension': file_extension,
            "SHA-256 Hash": sha256_hash
        }
    except Exception as e:
        print(f"Error extracting features from file {file_path}: {e}")
        return None


# Function to predict file safety
def predict_file_safety(file_path):
    features = extract_features(file_path)

    if features is None:
        print(f"Skipping file {file_path} due to extraction errors.")
        return

    df = pd.DataFrame([features])

    df['Extension'] = label_encoder.fit_transform(df['Extension'])
    df['SHA-256 Hash'] = label_encoder.fit_transform(df['SHA-256 Hash'])

    df_scaled = (df - scaler_mean) / scaler_scale

    prediction = rf_model.predict(df_scaled)

    if prediction == 1:
        print(f"The file {file_path} is classified as Safe.")
    else:
        print(f"The file {file_path} is classified as Unsafe.")

        # Suggest further analysis for unsafe files
        print("Further analysis recommended:")

        # Hash of the file (MD5, SHA256)
        sha256_hash = modify.calculate_hash(file_path, "sha256")
        if sha256_hash:
            print(f"SHA256 Hash: {sha256_hash}")
            hash_check.check_file_hash(sha256_hash)


# Define your folder path to scan files
test_folder = os.path.join(os.path.expanduser("~"), "Desktop", "test")

for filename in os.listdir(test_folder):
    file_path = os.path.join(test_folder, filename)

    if os.path.isfile(file_path):
        print(f"Scanning file: {filename}")
        predict_file_safety(file_path)
