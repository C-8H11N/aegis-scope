import fs from "node:fs";
import vm from "node:vm";

const html = fs.readFileSync("src/aegisscope/web/static/index.html", "utf8");
const javascript = fs.readFileSync("src/aegisscope/web/static/app.js", "utf8");
new vm.Script(javascript, { filename: "app.js" });

const ids = [...html.matchAll(/id="([^"]+)"/g)].map((match) => match[1]);
const duplicateIds = [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))];
const translationKeys = [
  ...new Set(
    [...html.matchAll(/data-i18n(?:-placeholder)?="([^"]+)"/g)].map((match) => match[1]),
  ),
];
const missingKeys = translationKeys.filter((key) => {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return (javascript.match(new RegExp(`\\b${escaped}:`, "g")) || []).length < 2;
});

if (duplicateIds.length || missingKeys.length) {
  process.stderr.write(
    `${JSON.stringify({ duplicateIds, missingTranslationKeys: missingKeys }, null, 2)}\n`,
  );
  process.exitCode = 1;
} else {
  process.stdout.write("Frontend syntax, HTML IDs, and bilingual keys: OK\n");
}
