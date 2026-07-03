// Shim: Node.js 'net' module — not available in browser.
// tcp_client_interface.js imports this but we never use TCPClientInterface in browser.
export default {};
export const Socket = class {
    constructor() { throw new Error("TCP sockets not available in browser. Use WebsocketClientInterface instead."); }
};
