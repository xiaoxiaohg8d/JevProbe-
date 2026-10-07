// Native optional filter execution; transport is serialized, consumer unchanged.
import {createInterface} from "node:readline";
import {resolve} from "node:path";

const [target, runtime] = process.argv.slice(2);
const lines = createInterface({input: process.stdin, crlfDelay: Infinity})[Symbol.asyncIterator]();
const next = async () => {
  const row = await lines.next();
  if (row.done) throw new Error("missing transport input");
  return JSON.parse(row.value);
};
const initial = await next();
const {filterOutput} = await import(resolve(target, "src/filter.ts"));
const {defaultConfig} = await import(resolve(target, "src/config.ts"));
const {prepareEvaluationRequest} = await import(resolve(runtime, "pi-typesafe/package/dist/index.js"));
const config = defaultConfig().context.filter;
let ordinal = 0;
let queue: Promise<unknown> = Promise.resolve();
const judge = {evaluate: (request: any) => {
  const result = queue.then(async () => {
    const prepared = prepareEvaluationRequest(request);
    console.log(JSON.stringify({kind: "request", ordinal: ordinal++, request: prepared}));
    const reply = await next();
    if (reply.kind !== "response") throw new Error("unexpected response kind");
    return reply.response;
  });
  queue = result.catch(() => undefined);
  return result;
}};
const verdict = await filterOutput(initial.source, {
  tool: initial.tool, task: initial.task,
  ...(initial.command === undefined ? {} : {command: initial.command}),
  ...(initial.plan === undefined ? {} : {plan: initial.plan}),
}, {config, judge});
console.log(JSON.stringify({kind: "result", verdict, config, behavior: {
  filter_succeeded: verdict.ok,
  selected_text: verdict.ok ? verdict.text : null,
  kept_chunks: verdict.ok ? verdict.kept : null,
  fallback_reason: verdict.ok ? null : verdict.reason,
}}));
process.exit(0);
