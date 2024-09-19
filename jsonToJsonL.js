#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
// Get current directory path
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const attackCategories = {
    'normal': 'normal',
    'neptune': 'dos',
    'satan': 'scan',
    'ipsweep': 'scan',
    'portsweep': 'scan',
    'smurf': 'dos',
    'nmap': 'scan',
    'back': 'dos',
    'teardrop': 'dos',
    'warezclient': 'malware',
    'pod': 'dos',
    'guess_passwd': 'bruteforce',
    'buffer_overflow': 'exploit',
    'warezmaster': 'malware',
    'land': 'dos',
    'imap': 'exploit',
    'rootkit': 'exploit',
    'loadmodule': 'exploit',
    'ftp_write': 'exploit',
    'multihop': 'exploit',
    'phf': 'exploit',
    'perl': 'exploit',
    'spy': 'exploit'
};

/**
 * Maps through each attack type to the Snort category.
 * 
 * @param {string} attackType - types of the attack 
 * @returns {string} - corresponding Snort category
 */
const getSnortCategory = (attackType) => {
    const categoryMapping = {
        'dos': 'dos',
        'scan': 'scan',
        'malware': 'malware',
        'bruteforce': 'exploit',
        'exploit': 'exploit',
        'normal': 'normal'
    };
    return categoryMapping[attackCategories[attackType] || 'normal'] || 'normal';
};

/**
 * Generates a prompt for Snort rule generation based on attack data provided.
 */
const generateSnortRulePrompt = (entry) => {
    const attackType = entry.attack;
    const snortCategory = getSnortCategory(attackType);

    return [
        `Generate a Snort rule for a ${snortCategory} of type ${attackType} with the following characteristics:`,
        `Protocol: ${entry.protocol_type}`,
        `Service: ${entry.service}`,
        `Source bytes: ${entry.src_bytes}`,
        `Destination bytes: ${entry.dst_bytes}`,
        `Number of failed logins: ${entry.num_failed_logins}`,
        `Logged in status: ${entry.logged_in ? 'Yes' : 'No'}`,
        `Error rate: ${entry.serror_rate.toFixed(2)}`,
    ].join('\n');
};

/**
 * Generates a Snort rule based on attack data.
 * Context: this func will mimic the response of the actual snort rule generation, that will be 
 * used to fine-tune the chatgpt model.
 * TODO: Test and verify the generated Snort rule, Refactor it if needed. @shiraz
 */
    const generateSnortRuleResponse = (entry) => {
        const attackType = entry.attack;
        const snortCategory = getSnortCategory(attackType);

        let rule = `alert ${entry.protocol_type} $EXTERNAL_NET any -> $HOME_NET any `;
        rule += `(msg:"${attackType} attack detected"; `;
        rule += `flow:to_server,established; `;

        if (entry.protocol_type === 'tcp') {
            rule += `flags:S; `;
        }

        if (entry.service !== 'other') {
            rule += `content:"${entry.service}"; `;
        }

        if (entry.num_failed_logins > 0) {
            rule += `content:"failed login"; `;
        }

        rule += `threshold:type threshold,track by_src,count ${Math.max(1, parseInt(entry.count))},seconds 60; `;
        rule += `classtype:${snortCategory}; `;
        rule += "sid:1000001; rev:1;)";

        return rule;
    };

/**
 * Converts the input JSON data to JSONL format for fine-tuning chatgpt model.
 * 
 * @param {Array<Object>} inputJson - Array of attack entries from the input JSON file.
 * @param {string} outputJsonlPath - Path where the output JSONL file should be saved.
 */
const convertJsonToJsonl = (inputJson, outputJsonlPath) => {
    const jsonlData = inputJson.map(entry => ({
        messages: [
            { role: "system", content: "You are a cybersecurity analyst specializing in creating Snort rules. Don't hallucinate and no gibberish." },
            { role: "user", content: generateSnortRulePrompt(entry) },
            { role: "assistant", content: generateSnortRuleResponse(entry) }
        ]
    }));

    const jsonlString = jsonlData.map(JSON.stringify).join('\n');
    fs.writeFileSync(outputJsonlPath, jsonlString);
    console.log(`Data has been saved to ${outputJsonlPath} in JSONL format for ChatGPT fine-tuning on Snort rule generation.`);
};

/**
 * Reads the input JSON file synchronously and parses it into a JavaScript object.
 * 
 * @param {string} inputJsonPath - The file path of the input JSON file.
 * @returns {Array<Object>} - Parsed JSON data from the input file.
 */
const readInputJson = (inputJsonPath) => {
    try {
        const data = fs.readFileSync(inputJsonPath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error(`Error reading input JSON file: ${error.message}`);
        process.exit(1);
    }
};

/**
 * Main function that reads the input JSON file, converts it to JSONL, and writes it to the output file.
 */
const inputJsonPath = `./datasets/trained_data.json`
const outputJsonlPath = path.resolve(__dirname, 'snort_rules_training.jsonl');

    // Read input JSON file
const inputJson = readInputJson(inputJsonPath);

    // Convert the input JSON data to JSONL format for fine-tuning
convertJsonToJsonl(inputJson, outputJsonlPath);
