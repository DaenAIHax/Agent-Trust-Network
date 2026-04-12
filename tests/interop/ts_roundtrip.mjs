// Cross-language interop harness driven by tests/test_ts_interop.py.
// Modes:
//   encrypt --curve=ec|rsa --input=<path>  → read {recipient_pub_pem, payload, sig, session, sender, seq}
//                                              write {blob} to stdout as JSON
//   decrypt --input=<path>                 → read {recipient_priv_pem, blob, session, sender, seq}
//                                              write {payload, inner_signature} to stdout
import { readFileSync } from "node:fs";
import { encryptForAgent, decryptFromAgent } from "../../sdk-ts/dist/crypto.js";

const args = Object.fromEntries(
  process.argv.slice(3).map((a) => {
    const [k, v] = a.replace(/^--/, "").split("=");
    return [k, v];
  }),
);
const mode = process.argv[2];
const data = JSON.parse(readFileSync(args.input, "utf-8"));

if (mode === "encrypt") {
  const blob = encryptForAgent(
    data.payload,
    data.recipient_pub_pem,
    data.session_id,
    data.sender_agent_id,
    data.inner_signature,
    data.client_seq ?? null,
  );
  process.stdout.write(JSON.stringify({ blob }));
} else if (mode === "decrypt") {
  const [payload, inner_signature] = decryptFromAgent(
    data.blob,
    data.recipient_priv_pem,
    data.session_id,
    data.sender_agent_id,
    data.client_seq ?? null,
  );
  process.stdout.write(JSON.stringify({ payload, inner_signature }));
} else {
  process.stderr.write(`unknown mode: ${mode}\n`);
  process.exit(2);
}
