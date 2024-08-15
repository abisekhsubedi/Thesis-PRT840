**Thesis PRT 840**


The NSL-KDD dataset primarily categorizes attacks into four main categories:

DoS (Denial of Service): These attacks aim to overwhelm a system or network to prevent legitimate users from accessing it. Examples include:
`neptune, back, land, pod, smurf, teardrop, udpstorm, mailbomb, apache2, processtable, worm`
R2L (Remote to Local): These attacks exploit vulnerabilities to gain unauthorized access to a local system. Examples include:
`ftp_write, guess_passwd, imap, multihop, phf, spy, warezclient, warezmaster, sendmail, named, snmpgetattack, snmpguess, xlock, xsnoop, httptunnel`   
U2R (User to Root): These attacks allow a normal user to gain root privileges on a system. Examples include:
`buffer_overflow, Loadmodule, perl, rootkit, ps, sqlattack, xterm`
Probe: These attacks gather information about a system or network to find vulnerabilities. Examples include:
`ipsweep, nmap, portsweep, satan, mscan, saint`


Feature selection: 
DoS Attacks
High values: `duration, count, srv_count, dst_host_count, dst_host_srv_count`
Low values: `src_bytes, dst_bytes, wrong_fragment, urgent, hot, num_failed_logins, logged_in`
R2L Attacks
High values: `num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files, is_host_login, is_guest_login`
U2R Attacks
High values: `root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files`
Probe Attacks
High values: `count, srv_count, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate1`   

Low values: `src_bytes, dst_bytes, wrong_fragment, urgent, hot, num_failed_logins, logged_in`