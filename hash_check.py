import requests

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

    if response.status_code == 200:
        # If the response is successful, return the JSON data
        data = response.json()

        # Extract the analysis results from the response
        last_analysis_stats = data['data']['attributes']['last_analysis_stats']
        print(f"Malicious: {last_analysis_stats['malicious']}")
        print(f"Suspicious: {last_analysis_stats['suspicious']}")
        print(f"Undetected: {last_analysis_stats['undetected']}")

        # Optionally, print the detailed scan results
        scan_results = data['data']['attributes']['last_analysis_results']
        for engine, result in scan_results.items():
            print(f"{engine}: {result['category']}")

    elif response.status_code == 403:
        print("Access Denied: API key may be invalid or exceeded limit.")
    elif response.status_code == 404:
        print("File not found in the VirusTotal database.")
    else:
        print(f"Error {response.status_code}: Unable to fetch the data.")
