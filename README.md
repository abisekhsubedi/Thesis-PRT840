## NSL-KDD Dataset Attack Categories

### Attack Types

| **Category** | **Description** | **Examples** |
|--------------|-----------------|--------------|
| **DoS (Denial of Service)** | Attacks that aim to overwhelm a system or network to prevent legitimate users from accessing it. | `neptune, back, land, pod, smurf, teardrop, udpstorm, mailbomb, apache2, processtable, worm` |
| **R2L (Remote to Local)** | Attacks that exploit vulnerabilities to gain unauthorized access to a local system. | `ftp_write, guess_passwd, imap, multihop, phf, spy, warezclient, warezmaster, sendmail, named, snmpgetattack, snmpguess, xlock, xsnoop, httptunnel` |
| **U2R (User to Root)** | Attacks that allow a normal user to gain root privileges on a system. | `buffer_overflow, Loadmodule, perl, rootkit, ps, sqlattack, xterm` |
| **Probe** | Attacks that gather information about a system or network to find vulnerabilities. | `ipsweep, nmap, portsweep, satan, mscan, saint` |

---

### Feature Selection

| **Category** | **High Feature Values** | **Low Feature Values** |
|--------------|-------------------------|------------------------|
| **DoS** | `duration, count, srv_count, dst_host_count, dst_host_srv_count` | `src_bytes, dst_bytes, wrong_fragment, urgent, hot, num_failed_logins, logged_in` |
| **R2L** | `num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files, is_host_login, is_guest_login` | - |
| **U2R** | `root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files` | - |
| **Probe** | `count, srv_count, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate` | `src_bytes, dst_bytes, wrong_fragment, urgent, hot, num_failed_logins, logged_in` |



Steps:
1. pip install `requirement.txt`
2. npm install all the packages
3. Create a `.env` file and add your openai API key in your .env file.

Requirements:
1. python version 3 or above
2. node version 20 or above
