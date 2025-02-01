import os
import hashlib
import requests
import pandas as pd
from scipy.stats import entropy
from pathlib import Path


# Define the folder containing your files
test_folder = os.path.join(os.path.expanduser("~"), "Desktop", "test")
folder = os.path.join(os.path.expanduser("~"), "Desktop", "AI", "malicious_detection")

# Threshold for entropy
ENTROPY_THRESHOLD = 6
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.sh', '.dll', '.js', '.vbs']


# Function to calculate file hash
def calculate_hash(file_path, hash_type="md5"):
    """Calculate the hash of a file."""
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
    """Calculate the Shannon entropy of file content."""
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
API_KEY = '3e0d58c3db054e985a95dd2bfb41c05f53d7557c2d3638e0523cef27e0a2efa3'

# The base URL for VirusTotal API
URL = 'https://www.virustotal.com/api/v3/files/'


# Function to get the report of a file based on its hash
def check_file_hash(file_hash):
    headers = {
        'x-apikey': API_KEY
    }

    # Make a request to the VirusTotal API
    response = requests.get(URL + file_hash, headers=headers)
    suspicious_level = 0  # Default suspicion level

    if response.status_code == 200:
        # If the response is successful, return the JSON data
        data = response.json()

        # Extract the analysis results from the response
        last_analysis_stats = data['data']['attributes']['last_analysis_stats']

        # Increase suspicion if any malicious or suspicious results are found
        if last_analysis_stats['malicious'] > 0:
            suspicious_level += 2  # Increase suspicion significantly for malicious files
        elif last_analysis_stats['suspicious'] > 0:
            suspicious_level += 1  # Moderate increase for suspicious files

        # Optionally, print the detailed scan results
        scan_results = data['data']['attributes']['last_analysis_results']
        for engine, result in scan_results.items():
            print(f"{engine}: {result['category']}")

    elif response.status_code == 404:
        suspicious_level += 0
    else:
        print(f"Error {response.status_code}: Unable to fetch the data.")

    return suspicious_level

# Define suspicious conditions
def extract_features(folder_path):
    """Extract features from files in the given folder."""
    features = []

    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            try:
                # Get basic metadata
                file_stats = os.stat(file_path)
                size = file_stats.st_size
                creation_time = file_stats.st_ctime
                modification_time = file_stats.st_mtime
                access_time = file_stats.st_atime
                extension = Path(file_path).suffix.lower()

                # Calculate hashes
                sha256_hash = calculate_hash(file_path, "sha256")

                # Calculate entropy
                file_entropy = calculate_entropy(file_path)

                # Define suspicious conditions
                suspicion_level = 0

                # 1. Suspicious extensions
                if extension in SUSPICIOUS_EXTENSIONS:
                    suspicion_level += 1

                # 2. High entropy indicating possible obfuscation or compression
                if file_entropy > ENTROPY_THRESHOLD:
                    suspicion_level += 1

                # 3. If both suspicious extension and high entropy, check the file hash
                if suspicion_level == 1:  # This means both conditions are met
                    suspicion_level += check_file_hash(sha256_hash)

                # Label based on suspicion level
                if suspicion_level >= 2:
                    label = 0  # Unsafe (Malicious)
                else:
                    label = 1  # Safe

                # Append extracted features
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



# Extract features and save to CSV
features = extract_features(test_folder)
df = pd.DataFrame(features)

# Save as CSV
output_file = os.path.join(folder, "file_features.csv")
df.to_csv(output_file, index=False)
print(f"Features extracted and saved to {output_file}")
