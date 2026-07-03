// Shim: 'ws' WebSocket module — browser uses native WebSocket instead.
// websocket_client_interface.js dynamically imports this only in Node.js mode.
export default class WebSocket {
    constructor() { throw new Error("ws module not available in browser. Native WebSocket is used instead."); }
}
