import Packet from "../packet.js";
import Interface from "./interface.js";
import Runtime from "../utils/runtime.js";

class WebsocketClientInterface extends Interface {

    constructor(name, url) {
        super(name);
        this.url = url;
        this._reconnectDelay = 1000;    // current backoff (ms)
        this._reconnectMin = 1000;       // 1 second
        this._reconnectMax = 30000;      // 30 seconds max
    }

    connect() {
        if(Runtime.isBrowser()){
            this.connectInBrowser();
        } else {
            this.connectInNodeJs();
        }
    }

    connectInBrowser() {

        // connect to websocket
        this.websocket = new WebSocket(this.url);

        // connect to server
        this.websocket.addEventListener("open", () => {
            console.log(`Connected to: ${this.name} [${this.url}]`);
            // Reset backoff on successful connection
            this._reconnectDelay = this._reconnectMin;
        });

        // handle received data
        this.websocket.addEventListener('message', async (message) => {
            const arrayBuffer = await message.data.arrayBuffer();
            this.onDataReceived(Buffer.from(arrayBuffer));
        });

        // handle errors
        this.websocket.addEventListener('error', (error) => {
            this.onSocketError(error);
        });

        // handle socket close
        this.websocket.addEventListener('close', (event) => {
            this.onSocketClose(event);
        });

    }

    async connectInNodeJs() {

        // note: ws module is only available in NodeJS, browsers should use connectInBrowser()
        const { WebSocket } = await import("ws");

        // connect to websocket
        this.websocket = new WebSocket(this.url);

        // connect to server
        this.websocket.on("open", () => {
            console.log(`Connected to: ${this.name} [${this.url}]`);
            this._reconnectDelay = this._reconnectMin;
        });

        // handle received data
        this.websocket.on('message', async (data) => {
            this.onDataReceived(data);
        });

        // handle errors
        this.websocket.on('error', (error) => {
            this.onSocketError(error);
        });

        // handle socket close
        this.websocket.on('close', (code, reason) => {
            this.onSocketClose({ code, reason: reason?.toString() ?? "" });
        });

    }

    onSocketError(error) {
        console.error('Connection Error:', error?.message || error);
        // Don't reconnect here — the 'close' event always follows 'error'
        // and onSocketClose handles the reconnect with backoff.
    }

    onSocketClose(event) {
        // Log close reason when available
        const code = event?.code ?? "?";
        const reason = event?.reason ?? "";
        console.warn(`Connection Closed (code=${code}${reason ? ", reason=" + reason : ""}). Reconnecting in ${(this._reconnectDelay / 1000).toFixed(1)}s...`);

        // Exponential backoff: double delay each time, up to max
        const delay = this._reconnectDelay;
        this._reconnectDelay = Math.min(this._reconnectDelay * 2, this._reconnectMax);

        setTimeout(() => {
            this.connect();
        }, delay);
    }

    sendData(data) {
        this.websocket.send(data);
    }

    onDataReceived(data) {
        this.processIncoming(data);
    }

    processIncoming(data) {

        // fixme: skipping ifac packets for now
        if((data[0] & 0x80) === 0x80){
            console.log("IFAC packet received. SKIPPING FOR NOW");
            return;
        }

        // parse packet from bytes
        const packet = Packet.fromBytes(data);

        // pass to rns
        this.rns.onPacketReceived(packet, this);

    }

}

export default WebsocketClientInterface;
