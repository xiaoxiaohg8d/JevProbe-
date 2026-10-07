// Transport-only seam: native source, builders, preprocessing and consumers run unchanged.
// Dependencies are acquired separately with fixed versions and MIT notices retained.
import { createInterface } from "node:readline";
import { resolve } from "node:path";

const [target, runtime] = process.argv.slice(2);
const lines = createInterface({input: process.stdin, crlfDelay: Infinity})[Symbol.asyncIterator]();
const next = async () => {
  const row = await lines.next();
  if (row.done) throw new Error("missing transport input");
  return JSON.parse(row.value);
};
const initial = await next();
const {evaluateOutput, securityNotice} = await import(resolve(target, "src/output.ts"));
const {defaultConfig} = await import(resolve(target, "src/config.ts"));
const {prepareEvaluationRequest} = await import(resolve(runtime, "pi-typesafe/package/dist/index.js"));
const config = defaultConfig();
let ordinal = 0;
const judge = { evaluate: async (request: any) => {
  const prepared = prepareEvaluationRequest(request);
  console.log(JSON.stringify({kind: "request", ordinal: ordinal++, request: prepared}));
  const reply = await next();
  if (reply.kind !== "response") throw new Error("unexpected response kind");
  return reply.response;
}};
const verdict = await evaluateOutput(initial.tool, initial.source, initial.task, {
  security: config.security, context: config.context, judge, timeoutMs: 120000,
});
console.log(JSON.stringify({kind: "result", verdict, behavior: {
  suspicious: verdict.suspicious,
  security_notice: securityNotice(verdict) ?? null,
}, config: {security: config.security, context: config.context}}));
process.exit(0);
