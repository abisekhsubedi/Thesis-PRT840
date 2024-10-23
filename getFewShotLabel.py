from openai import OpenAI
import pandas as pd
import time
import csv

key = ""

file_path = './unknown.csv'
df = pd.read_csv(file_path, header=None)

packet_info_list = df[0].tolist()

classes = [
    "normal", "neptune", "guess_passwd", "mscan", "warezmaster", "apache2", 
    "satan", "processtable", "smurf", "back", "snmpguess", "saint", 
    "mailbomb", "snmpgetattack", "portsweep", "ipsweep", "httptunnel", 
    "nmap", "pod", "buffer_overflow", "multihop", "named", "ps", "sendmail", 
    "rootkit", "xterm", "teardrop", "xlock", "land", "xsnoop", "ftp_write", 
    "worm", "loadmodule", "perl", "sqlattack", "udpstorm", "phf", "imap"
]

#query OpenAI API
client = OpenAI(api_key=key)

def query_openai(packet_info):
    try:

        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"system", "content": "You are a classifier."},
                      {
                    "role": "user", 
                    "content": f"This is a packet information: {packet_info}. "
                               f"Determine the class that it belongs to. The possible classes are: {', '.join(classes)}. "
                               "Your answer should not lie outside of the above defined set of classes. "
                               "Just return the class as a single word without any extra explanation."
                }],
                max_tokens=2
        )
        print(res._request_id)
        return res.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error: {e}")
        return None

# Function to process the file in batches and avoid rate limits
def process_packets(packet_info_list, batch_size=100, delay=5):
    results = []
    for i in range(0, len(packet_info_list), batch_size):
        batch = packet_info_list[i:i + batch_size]
        batch_results = []
        for packet_info in batch:
            # Query the OpenAI API
            result = query_openai(packet_info)
            batch_results.append([packet_info, result])
            print(f"Processed packet: {packet_info[:50]}... => {result}")
        
        # Write interim results to avoid losing progress
        with open('output.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            for res in batch_results:
                writer.writerow(res)
        
        # Delay between batches to avoid rate limits
        print(f"Processed {len(results) + len(batch_results)} packets. Sleeping for {delay} seconds.")
        results.extend(batch_results)
        time.sleep(delay)
    
    return results


# run the function
process_packets(packet_info_list)
