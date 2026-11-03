/** Runs in a browser `Worker` or in Node `worker_threads`. */
import { answerScanRequest, type ScanWorkerRequest } from "./anonymous-scan.js";

const nodePort = globalThis.process?.getBuiltinModule?.("node:worker_threads")?.parentPort;

if (nodePort !== undefined && nodePort !== null) {
  nodePort.on("message", (request: ScanWorkerRequest) => {
    void answerScanRequest(request).then((reply) => nodePort.postMessage(reply));
  });
} else {
  globalThis.addEventListener("message", (event) => {
    const { data } = event as MessageEvent<ScanWorkerRequest>;
    void answerScanRequest(data).then((reply) => globalThis.postMessage(reply));
  });
}
