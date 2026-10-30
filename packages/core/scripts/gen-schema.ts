// stack.yaml の JSON Schema を配布用に出力する（8-1）
// 使い方：pnpm --filter @ichiji/core gen:schema
import { writeFileSync } from "node:fs";
import { stackJsonSchema } from "../src/stack";

const out = new URL("../../../apps/web/public/schemas/stack.schema.json", import.meta.url);
writeFileSync(out, `${JSON.stringify(stackJsonSchema(), null, 2)}\n`);
console.log(`wrote ${out.pathname}`);
