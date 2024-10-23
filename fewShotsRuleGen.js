import { readFileSync, writeFileSync } from 'node:fs';
import OpenAI from "openai";

const openai = new OpenAI({ /* API key is changed after every use */
    apiKey: ""
});

let rules = [];
const data = readFileSync("./util/snortrule.txt", 'utf8');

console.log("\nFile read successfully >>>>>>");
rules = data.split('\n').filter(rule => rule.trim() !== '');


/*
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
*/

/*
model : gpt-40-mini token
{
  prompt_tokens: 16213,
  completion_tokens: 1168,
  total_tokens: 17381,
  prompt_tokens_details: { cached_tokens: 14720 },
  completion_tokens_details: { reasoning_tokens: 0 }
}
*/
try {
    const completion = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
            {
             role: "system",
             content: `
             You are a cybersecurity expert. I am passing you network traffic packet information and attack class as example. Your task is learn this and generate snort rules for user command\
  For 'neptune' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'REJ', 'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 229, 'srv_count': 10, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 0.04, 'diff_srv_rate': 0.06, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.04, 'dst_host_diff_srv_rate': 0.06, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 1.0, 'dst_host_srv_rerror_rate': 1.0, 'label': 'neptune'  \

  For 'normal' class, this is how packet looks like.\
  'duration': 2, 'protocol_type': 'tcp', 'service': 'ftp_data', 'flag': 'SF', 'src_bytes': 12983, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 134, 'dst_host_srv_count': 86, 'dst_host_same_srv_rate': 0.61, 'dst_host_diff_srv_rate': 0.04, 'dst_host_same_src_port_rate': 0.61, 'dst_host_srv_diff_host_rate': 0.02, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'normal'  \

  For 'saint' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'icmp', 'service': 'eco_i', 'flag': 'SF', 'src_bytes': 20, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 65, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 1.0, 'dst_host_count': 3, 'dst_host_srv_count': 57, 'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0, 'dst_host_srv_diff_host_rate': 0.28, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'saint'  \

  For 'mscan' class, this is how packet looks like.\
  'duration': 1, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'RSTO', 'src_bytes': 0, 'dst_bytes': 15, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 8, 'serror_rate': 0.0, 'srv_serror_rate': 0.12, 'rerror_rate': 1.0, 'srv_rerror_rate': 0.5, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.75, 'dst_host_count': 29, 'dst_host_srv_count': 86, 'dst_host_same_srv_rate': 0.31, 'dst_host_diff_srv_rate': 0.17, 'dst_host_same_src_port_rate': 0.03, 'dst_host_srv_diff_host_rate': 0.02, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.83, 'dst_host_srv_rerror_rate': 0.71, 'label': 'mscan'  \

  For 'guess_passwd' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 129, 'dst_bytes': 174, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 1, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.01, 'dst_host_srv_serror_rate': 0.01, 'dst_host_rerror_rate': 0.02, 'dst_host_srv_rerror_rate': 0.02, 'label': 'guess_passwd'  \

  For 'smurf' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'icmp', 'service': 'ecr_i', 'flag': 'SF', 'src_bytes': 520, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 511, 'srv_count': 511, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 46, 'dst_host_srv_count': 59, 'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0, 'dst_host_srv_diff_host_rate': 0.14, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'smurf'  \

  For 'apache2' class, this is how packet looks like.\
  'duration': 805, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'RSTR', 'src_bytes': 76944, 'dst_bytes': 1, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 12, 'srv_count': 12, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 241, 'dst_host_srv_count': 238, 'dst_host_same_srv_rate': 0.99, 'dst_host_diff_srv_rate': 0.01, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.07, 'dst_host_srv_rerror_rate': 0.07, 'label': 'apache2'  \

  For 'satan' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'REJ', 'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 483, 'srv_count': 1, 'serror_rate': 0.05, 'srv_serror_rate': 0.0, 'rerror_rate': 0.92, 'srv_rerror_rate': 1.0, 'same_srv_rate': 0.0, 'diff_srv_rate': 1.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 1.0, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.96, 'dst_host_srv_rerror_rate': 1.0, 'label': 'satan'  \

  For 'buffer_overflow' class, this is how packet looks like.\
  'duration': 8, 'protocol_type': 'tcp', 'service': 'ftp', 'flag': 'SF', 'src_bytes': 220, 'dst_bytes': 688, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 4, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 4, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 53, 'dst_host_srv_count': 27, 'dst_host_same_srv_rate': 0.51, 'dst_host_diff_srv_rate': 0.08, 'dst_host_same_src_port_rate': 0.02, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'buffer_overflow'  \

  For 'back' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF', 'src_bytes': 54540, 'dst_bytes': 8314, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 2, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 1, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 4, 'srv_count': 24, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.08, 'dst_host_count': 255, 'dst_host_srv_count': 250, 'dst_host_same_srv_rate': 0.98, 'dst_host_diff_srv_rate': 0.01, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.06, 'dst_host_srv_rerror_rate': 0.06, 'label': 'back'  \

  For 'warezmaster' class, this is how packet looks like.\
  'duration': 282, 'protocol_type': 'tcp', 'service': 'ftp', 'flag': 'SF', 'src_bytes': 160, 'dst_bytes': 599, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 2, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 1, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 37, 'dst_host_same_srv_rate': 0.15, 'dst_host_diff_srv_rate': 0.02, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.44, 'dst_host_srv_rerror_rate': 0.0, 'label': 'warezmaster'  \

  For 'snmpgetattack' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'udp', 'service': 'private', 'flag': 'SF', 'src_bytes': 105, 'dst_bytes': 146, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 2, 'srv_count': 2, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 9, 'dst_host_srv_count': 9, 'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.11, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'snmpgetattack'  \

  For 'processtable' class, this is how packet looks like.\
  'duration': 7428, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 0, 'dst_bytes': 44, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 217, 'dst_host_same_srv_rate': 0.85, 'dst_host_diff_srv_rate': 0.03, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.33, 'dst_host_srv_serror_rate': 0.39, 'dst_host_rerror_rate': 0.12, 'dst_host_srv_rerror_rate': 0.06, 'label': 'processtable'  \

  For 'pod' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'icmp', 'service': 'ecr_i', 'flag': 'SF', 'src_bytes': 1480, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 1, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 1, 'dst_host_srv_count': 25, 'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0, 'dst_host_srv_diff_host_rate': 0.52, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'pod'  \

  For 'httptunnel' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'other', 'flag': 'REJ', 'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 13, 'dst_host_same_srv_rate': 0.05, 'dst_host_diff_srv_rate': 0.02, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.06, 'dst_host_srv_rerror_rate': 1.0, 'label': 'httptunnel'  \

  For 'nmap' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'SH', 'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 1.0, 'srv_serror_rate': 1.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 30, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.03, 'dst_host_diff_srv_rate': 1.0, 'dst_host_same_src_port_rate': 1.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 1.0, 'dst_host_srv_serror_rate': 1.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'nmap'  \

  For 'ps' class, this is how packet looks like.\
  'duration': 31, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 197, 'dst_bytes': 1608, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 1, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 1, 'root_shell': 0, 'su_attempted': 0, 'num_root': 1, 'num_file_creations': 2, 'num_shells': 1, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 248, 'dst_host_srv_count': 32, 'dst_host_same_srv_rate': 0.13, 'dst_host_diff_srv_rate': 0.03, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'ps'  \

  For 'snmpguess' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'udp', 'service': 'private', 'flag': 'SF', 'src_bytes': 48, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 5, 'srv_count': 5, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 254, 'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.01, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'snmpguess'  \

  For 'ipsweep' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'icmp', 'service': 'eco_i', 'flag': 'SF', 'src_bytes': 8, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 14, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 1.0, 'dst_host_count': 2, 'dst_host_srv_count': 98, 'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0, 'dst_host_srv_diff_host_rate': 0.5, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'ipsweep'  \

  For 'mailbomb' class, this is how packet looks like.\
  'duration': 1, 'protocol_type': 'tcp', 'service': 'smtp', 'flag': 'SF', 'src_bytes': 2599, 'dst_bytes': 293, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 3, 'srv_count': 3, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 203, 'dst_host_same_srv_rate': 0.8, 'dst_host_diff_srv_rate': 0.13, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.19, 'dst_host_srv_rerror_rate': 0.0, 'label': 'mailbomb'  \

  For 'portsweep' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'RSTR', 'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 133, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.01, 'dst_host_diff_srv_rate': 0.65, 'dst_host_same_src_port_rate': 0.64, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.65, 'dst_host_srv_rerror_rate': 1.0, 'label': 'portsweep'  \

  For 'multihop' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'udp', 'service': 'other', 'flag': 'SF', 'src_bytes': 23, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 0.03, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'multihop'  \

  For 'named' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'ftp_data', 'flag': 'SF', 'src_bytes': 139508, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 3, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.33, 'dst_host_diff_srv_rate': 0.67, 'dst_host_same_src_port_rate': 0.33, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.67, 'dst_host_srv_rerror_rate': 0.0, 'label': 'named'  \

  For 'sendmail' class, this is how packet looks like.\
  'duration': 2, 'protocol_type': 'tcp', 'service': 'smtp', 'flag': 'SF', 'src_bytes': 4485, 'dst_bytes': 641, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 1, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 1, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 3, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 1.0, 'dst_host_count': 255, 'dst_host_srv_count': 7, 'dst_host_same_srv_rate': 0.03, 'dst_host_diff_srv_rate': 0.02, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.01, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.01, 'dst_host_srv_rerror_rate': 0.0, 'label': 'sendmail'  \

  For 'loadmodule' class, this is how packet looks like.\
  'duration': 84, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 277, 'dst_bytes': 1089, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 2, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 1, 'root_shell': 1, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 4, 'num_shells': 2, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 0.07, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.14, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.86, 'dst_host_srv_rerror_rate': 0.0, 'label': 'loadmodule'  \

  For 'xterm' class, this is how packet looks like.\
  'duration': 293, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 2773, 'dst_bytes': 41955, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 1, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 14, 'root_shell': 1, 'su_attempted': 0, 'num_root': 23, 'num_file_creations': 1, 'num_shells': 1, 'num_access_files': 1, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 5, 'dst_host_srv_count': 3, 'dst_host_same_srv_rate': 0.6, 'dst_host_diff_srv_rate': 0.4, 'dst_host_same_src_port_rate': 0.2, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'xterm'  \

  For 'worm' class, this is how packet looks like.\
  'duration': 9, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 4209, 'dst_bytes': 7919, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 113, 'dst_host_srv_count': 2, 'dst_host_same_srv_rate': 0.02, 'dst_host_diff_srv_rate': 0.04, 'dst_host_same_src_port_rate': 0.01, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'worm'  \

  For 'teardrop' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'udp', 'service': 'private', 'flag': 'SF', 'src_bytes': 28, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 3, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 10, 'srv_count': 10, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 35, 'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.29, 'dst_host_diff_srv_rate': 0.11, 'dst_host_same_src_port_rate': 0.29, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'teardrop'  \

  For 'rootkit' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'ftp_data', 'flag': 'SF', 'src_bytes': 45, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 50, 'dst_host_same_srv_rate': 0.2, 'dst_host_diff_srv_rate': 0.03, 'dst_host_same_src_port_rate': 0.2, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.29, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.02, 'dst_host_srv_rerror_rate': 0.0, 'label': 'rootkit'  \

  For 'xlock' class, this is how packet looks like.\
  'duration': 199, 'protocol_type': 'tcp', 'service': 'X11', 'flag': 'SF', 'src_bytes': 56124, 'dst_bytes': 17588, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 0.01, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'xlock'  \

  For 'perl' class, this is how packet looks like.\
  'duration': 40, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 258, 'dst_bytes': 2625, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 2, 'num_shells': 1, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 28, 'dst_host_srv_count': 2, 'dst_host_same_srv_rate': 0.04, 'dst_host_diff_srv_rate': 0.21, 'dst_host_same_src_port_rate': 0.04, 'dst_host_srv_diff_host_rate': 1.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.07, 'dst_host_srv_rerror_rate': 0.0, 'label': 'perl'  \

  For 'land' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'finger', 'flag': 'S0', 'src_bytes': 0, 'dst_bytes': 0, 'land': 1, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 2, 'serror_rate': 1.0, 'srv_serror_rate': 1.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 1.0, 'dst_host_count': 255, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 0.02, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 1.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'land'  \

  For 'xsnoop' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'X11', 'flag': 'S1', 'src_bytes': 1256, 'dst_bytes': 11240, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 1.0, 'srv_serror_rate': 1.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 0.02, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 1.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'xsnoop'  \

  For 'sqlattack' class, this is how packet looks like.\
  'duration': 2, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 398, 'dst_bytes': 3881, 'land': 0, 'wrong_fragment': 0, 'urgent': 1, 'hot': 1, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 1, 'su_attempted': 0, 'num_root': 4, 'num_file_creations': 3, 'num_shells': 1, 'num_access_files': 1, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 153, 'dst_host_srv_count': 19, 'dst_host_same_srv_rate': 0.12, 'dst_host_diff_srv_rate': 0.1, 'dst_host_same_src_port_rate': 0.01, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.02, 'dst_host_srv_rerror_rate': 0.0, 'label': 'sqlattack'  \

  For 'ftp_write' class, this is how packet looks like.\
  'duration': 20, 'protocol_type': 'tcp', 'service': 'ftp', 'flag': 'SF', 'src_bytes': 74, 'dst_bytes': 320, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 1, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 1, 'num_shells': 0, 'num_access_files': 1, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 1, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 23, 'dst_host_same_srv_rate': 0.09, 'dst_host_diff_srv_rate': 0.02, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.53, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.02, 'dst_host_srv_rerror_rate': 0.0, 'label': 'ftp_write'  \

  For 'imap' class, this is how packet looks like.\
  'duration': 91, 'protocol_type': 'tcp', 'service': 'imap4', 'flag': 'RSTO', 'src_bytes': 1352, 'dst_bytes': 291, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 0.02, 'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 1.0, 'label': 'imap'  \

  For 'udpstorm' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'udp', 'service': 'private', 'flag': 'SF', 'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 4, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.25, 'dst_host_diff_srv_rate': 0.5, 'dst_host_same_src_port_rate': 0.25, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0, 'label': 'udpstorm'  \

  For 'phf' class, this is how packet looks like.\
  'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'REJ', 'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 17, 'dst_host_srv_count': 17, 'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.06, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.06, 'dst_host_srv_rerror_rate': 0.06, 'label': 'phf'  \
             
             `   
            },
            {
                role: "user",

                content: `  
                        Below are the questions.Your task is to answer each question and give the answer in the following format:
                        
                        answer1,answer2,answer3
                
                        Questions:
generate snort rule for detecting TCP traffic on port 80. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for blocking all incoming ICMP echo requests. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for alerting on outbound SSH traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for blocking access to a specific IP address. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting FTP login attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting DNS queries to malicious domains. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting HTTP POST requests. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for alerting on failed SSH login attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting SQL injection attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for blocking BitTorrent traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting SYN flood attacks. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for monitoring DNS exfiltration. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting HTTP requests with suspicious user-agent strings. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for alerting on access to a specific URL pattern. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for blocking Telnet traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting brute-force login attempts on FTP. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting outgoing traffic to a blacklisted IP. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting web-based malware delivery. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting DDoS attacks. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for blocking traffic from a specific country. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for alerting on HTTP traffic containing specific keywords. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting attempts to access unauthorized websites. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting SSL/TLS handshakes. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting ARP spoofing attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting suspicious DNS tunneling activity. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting malicious PowerShell commands. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for blocking traffic to specific geographic locations. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting suspicious URL redirections. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting port scanning activity. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting HTTP traffic with hidden parameters. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting suspicious SMB traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting outgoing FTP data transfers. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting HTTP file uploads. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting brute-force RDP login attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting malware beaconing behavior. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for blocking outgoing email traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting suspicious login attempts to web applications. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting network traffic from specific browser versions. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting excessive DNS queries from a host. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting HTTP requests with specific headers. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting malicious content in email attachments. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting attempts to exploit web server vulnerabilities. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting suspicious outbound HTTPS traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for blocking access to specific URLs. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting attempts to disable antivirus software. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting ransomware communication. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting SQL injection attacks in web traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting unauthorized database access. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting buffer overflow attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
generate snort rule for detecting suspicious email domain lookups. Don't hallucinate. No explanation. Just the snort rule only.\n
                            `
            },
        ],
    });

    
    console.log(completion.usage);
    
    writeFileSync(
        "./output/few_shot_processed_rule_raw.txt",
        completion.choices[0].message.content,
        { flag: 'a' }
    )

   /* //Wait 1 second before the next API call
    if (i < Math.min(9, rules.length - 1)) {  // Don't wait after the last call
        console.log("Waiting for 1 second before next API call...");
        await sleep(1000);
    }
        */
} catch (error) {
    console.error(`Error:\n`, error.message);
}


// async function processRules() {
//     for (let i = 0; i < /*Math.min(10, rules.length )*/5; i++) {
//         try {
//             const completion = await openai.chat.completions.create({
//                 model: "gpt-4o-mini",
//                 messages: [
//                     {
//                         role: "user",
    
//                         content: `  
//                                 Below are the questions. There 3 question to answer. Your task is to generate snort Rule
                        
//                         generate snort rule for detecting TCP traffic on port 80. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking all incoming ICMP echo requests. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for alerting on outbound SSH traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking access to a specific IP address. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting FTP login attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting DNS queries to malicious domains. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting HTTP POST requests. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for alerting on failed SSH login attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting SQL injection attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking BitTorrent traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting SYN flood attacks. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for monitoring DNS exfiltration. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting HTTP requests with suspicious user-agent strings. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for alerting on access to a specific URL pattern. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking Telnet traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting brute-force login attempts on FTP. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting outgoing traffic to a blacklisted IP. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting web-based malware delivery. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting DDoS attacks. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking traffic from a specific country. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for alerting on HTTP traffic containing specific keywords. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting attempts to access unauthorized websites. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting SSL/TLS handshakes. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting ARP spoofing attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious DNS tunneling activity. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting malicious PowerShell commands. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking traffic to specific geographic locations. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious URL redirections. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting port scanning activity. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting HTTP traffic with hidden parameters. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious SMB traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting outgoing FTP data transfers. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting HTTP file uploads. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting brute-force RDP login attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting malware beaconing behavior. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking outgoing email traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious login attempts to web applications. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting network traffic from specific browser versions. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting excessive DNS queries from a host. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting HTTP requests with specific headers. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting malicious content in email attachments. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting attempts to exploit web server vulnerabilities. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious outbound HTTPS traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking access to specific URLs. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting attempts to disable antivirus software. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting ransomware communication. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting SQL injection attacks in web traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting unauthorized database access. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting buffer overflow attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious email domain lookups. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting TCP port scans. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for alerting on outgoing SMTP traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking traffic from certain network segments. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting unauthorized file transfers over SMB. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting command-and-control communication. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious SSL certificates. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking traffic based on a specific MAC address. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting HTTP basic authentication attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking all outbound traffic on port 21. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting DNS lookups for known phishing domains. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking outgoing VoIP traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for alerting on IPv6 traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting DNS requests for suspicious TLDs. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting malicious browser extensions. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking traffic to specific subnets. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting HTTP responses with unusual status codes. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious traffic to cloud services. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting SSL decryption attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting unauthorized API requests. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking access to specific DNS servers. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting malicious network scripts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting unusual traffic volume on specific ports. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking non-standard HTTP methods. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting unauthorized SNMP traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious HTTP redirects. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting attempts to tamper with log files. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting malicious IRC traffic. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting DNS amplification attacks. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting outgoing HTTP traffic to known C2 servers. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious SSH tunneling. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking access to TOR exit nodes. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting encrypted traffic over non-standard ports. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting brute-force attacks against databases. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking inbound UDP traffic on port 53. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting attempts to exploit Heartbleed vulnerability. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting outbound DNS exfiltration attempts. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious HTTP cookies. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting malicious email attachments over IMAP. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting outgoing traffic to TOR relays. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting SSL certificate mismatches. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking access to specific cloud storage services. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting DNS requests for dynamic DNS services. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting attempts to enumerate open ports. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting outgoing HTTP traffic with suspicious referrers. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking access to specific social media sites. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting unusual DNS query patterns. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting large data uploads over HTTP. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for blocking access to malware distribution sites. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting suspicious IPv6 extension headers. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     generate snort rule for detecting traffic containing sensitive information like credit card numbers. Don't hallucinate. No explanation. Just the snort rule only.\n
//                                     `
//                     },
//                 ],
//             });

//             console.log(`Processed rule ${i + 1}:`);
//             console.log(completion.choices[0].message.content);
//             writeFileSync(
//                 "./processed_rules.csv",
//                 completion.choices[0].message.content.split('\n').join(',') + '\n',
//                 { flag: 'a' }
//             )
//             // Wait 1 second before the next API call
//             // if (i < Math.min(9, rules.length - 1)) {  // Don't wait after the last call
//             //     console.log("Waiting for 1 second before next API call...");
//             //     await sleep(1000);
//             // }
//         } catch (error) {
//             console.error(`Error processing rule ${i + 1}:`, error.message);
//         }
//     }
// }

// processRules().catch(console.error);
