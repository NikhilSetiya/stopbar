// A mock stopbard: an in-process HTTP server that records each request and
// answers with whatever the test's responder returns.

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after } from "node:test";
import { Client, type ClientOptions } from "stopbar";

export type Responder = (path: string, body: any, method: string) => [number, unknown];
export interface Mock { url: string; last: { body: any; auth?: string; path?: string; method?: string }; seen: [string, any][] }

export const servers: Server[] = [];
after(() => servers.forEach((s) => s.close().closeAllConnections()));

export async function serve(responder: Responder): Promise<Mock> {
  const mock: Mock = { url: "", last: { body: null }, seen: [] };
  const srv = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : null;
      mock.last = { body, auth: req.headers.authorization, path: req.url, method: req.method };
      mock.seen.push([req.url ?? "", body]);
      const [status, out] = responder(req.url ?? "", body, req.method ?? "GET");
      res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(out));
    });
  });
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  mock.url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  return mock;
}

export const client = (m: Mock, o: ClientOptions = {}) => new Client(m.url, { tenant: "demo", agentId: "wallet-agent", ...o });

export const evm = () => Client.evmTx({
  chainId: 8453, from: "0x" + "1".repeat(40), to: "0x" + "2".repeat(40), valueWei: "1000", txNonce: "0",
  gasLimit: "21000", maxFeePerGas: "200000000", maxPriorityFeePerGas: "100000000",
});
