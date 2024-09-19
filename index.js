import 'dotenv/config';
import fs from 'node:fs/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import OpenAI from "openai";

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

let rules = [];
const data = readFileSync("./snortrule.txt", 'utf8');

console.log("File read successfully");
rules = data.split('\n').filter(rule => rule.trim() !== '');

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function processRules() {
    for (let i = 0; i < Math.min(10, rules.length); i++) {
        try {
            const completion = await openai.chat.completions.create({
                model: "ft:gpt-4o-mini-2024-07-18:personal::A4GokpKD",
                messages: [
                    {
                        role: "user",
                        content: rules[i]
                    },
                ]
            });

            console.log(`Processed rule ${i + 1}:`);
            console.log(completion.choices[0].message.content);
            writeFileSync("./processed_rules.txt", completion.choices[0].message.content + '\n', { flag: 'a' });

            // Wait 1 second before the next API call
            if (i < Math.min(9, rules.length - 1)) {  // Don't wait after the last call
                console.log("Waiting for 1 second before next API call...");
                await sleep(1000);
            }
        } catch (error) {
            console.error(`Error processing rule ${i + 1}:`, error.message);
        }
    }
}

processRules().catch(console.error);

// const completion = await openai.chat.completions.create({
//     model: "ft:gpt-4o-mini-2024-07-18:personal::A4GokpKD",
//     messages: [
//         {
//             role: "user",
//             content: `Generate a Snort rule for detecting DDos. Don't hallucinate and no gibberish.`
//         },
//     ]
// });

// console.log(completion.choices[0].message.content);