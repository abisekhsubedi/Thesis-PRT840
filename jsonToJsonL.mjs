#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

// Get current directory path
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Parse command-line arguments using yargs
const argv = yargs(hideBin(process.argv))
    .version('1.0.0')
    .description('Tool to generate Snort rules using GenAI')
    .option('input', {
        alias: 'i',
        describe: 'Path to the input JSON file',
        type: 'string',
        demandOption: true
    }).argv;

// Define attack categories for Snort rules
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
 * @returns {string} - The corresponding Snort category
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
 * Generates a prompt for Snort rule generation based on attack data.
 * 
 * @param {Object} entry - A dataset entry containing attack details.
 * @param {string} entry.attack - Type of attack.
 * @param {string} entry.protocol_type - Protocol used in the attack (e.g., 'tcp').
 * @param {string} entry.service - Service involved in the attack (e.g., 'ftp_data').
 * @param {number} entry.src_bytes - Number of bytes sent by the source.
 * @param {number} entry.dst_bytes - Number of bytes sent by the destination.
 * @param {number} entry.num_failed_logins - Number of failed login attempts.
 * @param {boolean} entry.logged_in - Whether the attacker was logged in.
 * @param {number} entry.serror_rate - Error rate for the attack.
 * @returns {string} - A prompt to be used for generating Snort rules.
 */

const generateSnortRulePrompt = (entry) => {
    const attackType = entry.attack;
    const snortCategory = getSnortCategory(attackType);

    return [
        `Generate a Snort rule for a ${snortCategory} attack of type ${attackType} with the following characteristics:`,
        `Protocol: ${entry.protocol_type}`,
        `Service: ${entry.service}`,
        `Source bytes: ${entry.src_bytes}`,
        `Destination bytes: ${entry.dst_bytes}`,
        `Number of failed logins: ${entry.num_failed_logins}`,
        `Logged in status: ${entry.logged_in ? 'Yes' : 'No'}`,
        `Error rate: ${entry.serror_rate.toFixed(2)}`,
        "Please create a Snort rule that would detect this type of attack."
    ].join('\n');
};

/**
 * Generates a Snort rule based on attack data.
 * 
 * @param {Object} entry - A dataset entry containing attack details.
 * @param {string} entry.attack - Type of attack.
 * @param {string} entry.protocol_type - Protocol used in the attack (e.g., 'tcp').
 * @param {string} entry.service - Service involved in the attack (e.g., 'ftp_data').
 * @param {number} entry.num_failed_logins - Number of failed login attempts.
 * @param {number} entry.count - Number of occurrences of the attack.
 * @returns {string} - A Snort rule to detect the attack.
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
 * Converts the input JSON data to JSONL format for fine-tuning.
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
const main = () => {
    const inputJsonPath = path.resolve(__dirname, argv.input);
    const outputJsonlPath = path.resolve(__dirname, 'snort_rules_training.jsonl');

    // Read input JSON file
    const inputJson = readInputJson(inputJsonPath);

    // Convert the input JSON data to JSONL format for fine-tuning
    convertJsonToJsonl(inputJson, outputJsonlPath);
};

// Execute the main function
main();
