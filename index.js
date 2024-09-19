#!/usr/bin/env node

// const path = require('path');
// const fs = require('fs');
// const axios = require('axios');
// const yargs = require('yargs/yargs');
// const {hideBin} = require('yargs/helpers');

// // Parse command line arguments.
// const argv = yargs(hideBin(process.argv))
//     .version('1.0.0')
//     .describe('tool to generate snort rules using GenAI')
//     .option('prompt', {
//         alias: 'p',
//         describe: 'prompt for user input',
//         type: 'string',
//         demandOption: true
//     }).argv;

// if (!argv.prompt) {
//     console.log('prompt is required');
//     process.exit(2);
// }

import OpenAI from "openai";
// what's wrong with API keys
const openai = new OpenAI({
    apiKey: ''
});

async function generateSnortRule() {
    const completion = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
            {
                role: "system",
                content: "You are a helpful assistant that generates Snort rules based on user input."
            },
            {
                role: "user",
                content: "Generate a Snort rule for detecting SQL injection attacks."
            }
        ]
    })
    console.log(completion.choices[0].message);
}
generateSnortRule()
