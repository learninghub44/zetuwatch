import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const webDirectory = fileURLToPath(new URL("../apps/web/", import.meta.url));
const htmlFiles = readdirSync(webDirectory)
  .filter((file) => file.endsWith(".html"))
  .sort();

let checkedScripts = 0;
for (const file of htmlFiles) {
  const html = readFileSync(join(webDirectory, file), "utf8");
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)];

  scripts.forEach((match, index) => {
    const source = match[1].trim();
    if (!source) return;
    try {
      // Parse only. Browser globals are intentionally not executed in CI.
      new Function(source);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(file + ": inline script " + (index + 1) + ": " + message);
    }
    checkedScripts += 1;
  });
}

if (checkedScripts === 0) throw new Error("No inline browser scripts were found to validate.");
console.log("Syntax-checked " + checkedScripts + " inline scripts across " + htmlFiles.length + " HTML files.");
