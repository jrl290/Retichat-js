import Cryptography from "../cryptography.js";

class Interface {

    // Standard RNS interface modes
    static MODE_FULL          = 1;
    static MODE_POINT_TO_POINT = 2;
    static MODE_ACCESS_POINT  = 3;
    static MODE_ROAMING       = 4;
    static MODE_BOUNDARY      = 5;
    static MODE_GATEWAY       = 6;

    constructor(name) {
        this.rns = null;
        this.name = name;
        this.hash = this.getHash();
    }

    setReticulumInstance(rns) {
        this.rns = rns;
    }

    getHash() {
        return Cryptography.sha256(this.name);
    }

    /**
     * Send data to from this interface.
     * This method should be implemented by subclasses.
     * @param data the data to send
     */
    sendData(data) {
        throw new Error("sendData should be implemented by Interface subclasses!");
    }

}

export default Interface;
