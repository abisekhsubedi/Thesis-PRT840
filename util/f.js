import * as fs from "node:fs/promises";
import * as fs_ from "node:fs";

try {
    // const filePath = new URL(
    //   "../output/few_shot_processed_rule_raw.txt",
    //   import.meta.url
    // );
    // TODO: fix the code later on 
    const filePath = new URL(
        "../output/zero_shot_processed_rule_raw.txt",
        import.meta.url
      );
    let contents = await fs.readFile(filePath, { encoding: "utf8" });
    contents = contents.replace(/```/g, "").trim();
    contents = contents
      .split("\n")
      .map((line) => `${line.trim()}`)
      .filter((line) => line.length > 2);
    // fs_.writeFileSync(
    //   "../output/few_shots_processed_rule.json",
    //   JSON.stringify(contents)
    // );
    // TODO: fix the code later on
    fs_.writeFileSync(
        "../output/zero_shots_processed_rule.json",
        JSON.stringify(contents)
      );
  } catch (e) {
    console.log(e);
  }