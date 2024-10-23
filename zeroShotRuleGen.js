import { readFileSync, writeFileSync } from 'node:fs';
import OpenAI from "openai";

const openai = new OpenAI({
    apiKey: ""
});

let rules = [];
const data = readFileSync("./util/snortrule.txt", 'utf8');

console.log("File read successfully");
rules = data.split('\n').filter(rule => rule.trim() !== '');


/*
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
*/

try {
    const completion = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
            {
                role: "user",

                content: `  
                        Below are the questions. Your task is to answer each question and give the answer in the following format:
                        
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
        "./output/zero_shot_processed_rule_raw.txt",
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
