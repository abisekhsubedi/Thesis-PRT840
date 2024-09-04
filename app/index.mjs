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

// // load training data
// const loadTrainingData = async () => {
//     try {
//         const data = await fs.readFileSync(path.resolve(__dirname, 'datasets','train_data.json'), 'utf8');
//         return JSON.parse(data);
//     } catch (error) {
//         console.error('Error loading training data:', error.message);
//         process.exit(1);
//     }
// }


// // Snort Rule generator.
// const generateSnortRule = async (prompt) => {
//     const API_KEY = process.env.OPENAI_API_KEY;

//     try {
//         const response = await axios.post(
//             'https://api.openai.com/v1/engines/gpt-4/completions',
//             {
//                 prompt: prompt,
//                 max_tokens: 150
//             },
//             {
//                 headers: {
//                     'Authorization': `Bearer ${API_KEY}`,
//                     'Content-Type': 'application/json',
//                 }
//             }

//         )
//        console.log(`Generated Snort Rule: ${response.data.choices[0].text}`); 
//     } catch (error) {
//         console.error('Error generating Snort rule:', error.response ? error.response.data : error.message);
//     }
// }

// const trainingData = loadTrainingData();

// generateSnortRule(argv.prompt, trainingData)

import OpenAI from "openai";
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
    // return completion.choices[0].message;
}
generateSnortRule()
