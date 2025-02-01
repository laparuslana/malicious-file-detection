import os
import hashlib
import pandas as pd
from scipy.stats import entropy
from pathlib import Path
import requests

test_folder = os.path.join(os.path.expanduser("~"), "Desktop", "testFolder")
folder = os.path.join(os.path.expanduser("~"), "Desktop", "AI", "malicious_detection", "model")

ENTROPY_THRESHOLD = 7.5
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.sh', '.dll', '.js', '.vbs']

# Function to calculate file hash
def calculate_hash(file_path, hash_type="md5"):
    hash_func = getattr(hashlib, hash_type)()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return 0


# Function to calculate file entropy
def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            if not data:
                return 0
            prob = [float(data.count(b)) / len(data) for b in set(data)]
            return entropy(prob, base=2)
    except Exception as e:
        print(f"Error calculating entropy for {file_path}: {e}")
        return 0

# Replace this with your VirusTotal API key
API_KEY = '***'

# The base URL for VirusTotal API
URL = 'https://www.virustotal.com/api/v3/files/'


# Function to get the report of a file based on its hash
def check_file_hash(file_hash):
    headers = {
        'x-apikey': API_KEY
    }

    response = requests.get(URL + file_hash, headers=headers)
    suspicious_level = 0

    if response.status_code == 200:
        data = response.json()

        last_analysis_stats = data['data']['attributes']['last_analysis_stats']

        if last_analysis_stats['malicious'] > 0:
            suspicious_level += 2
        elif last_analysis_stats['suspicious'] > 0:
            suspicious_level += 1

        scan_results = data['data']['attributes']['last_analysis_results']
        for engine, result in scan_results.items():
            print(f"{engine}: {result['category']}")

    elif response.status_code == 404:
        suspicious_level += 0
    else:
        print(f"Error {response.status_code}: Unable to fetch the data.")

    return suspicious_level


def extract_features(folder_path):
    features = []

    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            try:
                file_stats = os.stat(file_path)
                size = file_stats.st_size
                creation_time = file_stats.st_ctime
                modification_time = file_stats.st_mtime
                access_time = file_stats.st_atime
                extension = Path(file_path).suffix.lower()

                sha256_hash = calculate_hash(file_path, "sha256")

                file_entropy = calculate_entropy(file_path)

                suspicion_level = 0

                if extension in SUSPICIOUS_EXTENSIONS:
                    suspicion_level += 1

                if file_entropy > ENTROPY_THRESHOLD:
                    suspicion_level += 1

                if suspicion_level == 1:
                    suspicion_level += check_file_hash(sha256_hash)

                if suspicion_level >= 2:
                    label = 0  # Unsafe
                else:
                    label = 1  # Safe

                features.append({
                    "File Name": file_name,
                    "Size (bytes)": size,
                    "Creation Time": creation_time,
                    "Modification Time": modification_time,
                    "Access Time": access_time,
                    "Extension": extension,
                    "SHA-256 Hash": sha256_hash,
                    "Entropy": file_entropy,
                    "Label": label
                })

            except Exception as e:
                print(f"Error processing {file_name}: {e}")

    return features


features = extract_features(test_folder)
df = pd.DataFrame(features)

# Save as CSV
output_file = os.path.join(folder, "file_features_with_labels.csv")
df.to_csv(output_file, index=False)
print(f"Features extracted and saved to {output_file}")
