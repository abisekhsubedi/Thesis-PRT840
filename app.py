# %%
# Import necessary libraries
import pandas as pd
import json

# %%
# Define the attack categories
attack_categories = {
    'normal': 'Normal Traffic',
    'neptune': 'Denial of Service (DoS)',
    'satan': 'Scanning and Reconnaissance',
    'ipsweep': 'Scanning and Reconnaissance',
    'portsweep': 'Scanning and Reconnaissance',
    'smurf': 'Denial of Service (DoS)',
    'nmap': 'Scanning and Reconnaissance',
    'back': 'Denial of Service (DoS)',
    'teardrop': 'Denial of Service (DoS)',
    'warezclient': 'Malware and Illegal Software Distribution',
    'pod': 'Denial of Service (DoS)',
    'guess_passwd': 'Brute Force and Unauthorized Access',
    'buffer_overflow': 'Exploits and Vulnerabilities',
    'warezmaster': 'Malware and Illegal Software Distribution',
    'land': 'Denial of Service (DoS)',
    'imap': 'Protocol-Specific Attacks',
    'rootkit': 'Exploits and Vulnerabilities',
    'loadmodule': 'Exploits and Vulnerabilities',
    'ftp_write': 'Brute Force and Unauthorized Access',
    'multihop': 'Miscellaneous',
    'phf': 'Exploits and Vulnerabilities',
    'perl': 'Exploits and Vulnerabilities',
    'spy': 'Miscellaneous'
}

# %%
# Function to generate and save JSON file
def generate_json_pipeline(csv_file_path, json_file_path):
    # Add the column labels
    columns = (['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
                'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
                'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
                'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
                'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
                'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
                'dst_host_srv_rerror_rate', 'attack', 'level'])

# %%
    # Load the dataset
    df_train = pd.read_csv(csv_file_path, header=None, names=columns)

    # Map the attack types to categories
    df_train['attack_category'] = df_train['attack'].map(attack_categories)

    # Convert the DataFrame into a list of dictionaries (each dictionary is a row)
    json_output = df_train.to_dict(orient='records')

    # Save the list of dictionaries as a JSON file
    with open(json_file_path, 'w') as json_file:
        json.dump(json_output, json_file, indent=4)

    print(f"Data has been saved to {json_file_path} in JSON format")

# %%
# Run the pipeline to generate JSON
csv_file_path = './datasets/KDD/KDDTrain+_20Percent.txt'
json_file_path = './datasets/train_data.json'
# %%
# Generate JSON file >> available at ./datasets/train_data.json
generate_json_pipeline(csv_file_path, json_file_path)
