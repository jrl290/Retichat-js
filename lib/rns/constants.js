class Constants {

    // length of truncated hashes (128 bits = 16 bytes, matching Python Reticulum)
    static TRUNCATED_HASHLENGTH_IN_BITS = 128;
    static TRUNCATED_HASHLENGTH_IN_BYTES = this.TRUNCATED_HASHLENGTH_IN_BITS / 8;

    // Wire protocol sizes. Reference: RNS/Reticulum.py, RNS/Identity.py.
    // These are protocol constants shared by every node on the network, not
    // tunables — changing one makes us incompatible with everything else.
    static MTU = 500;
    static IFAC_MIN_SIZE = 1;
    static HEADER_MINSIZE = 2 + 1 + this.TRUNCATED_HASHLENGTH_IN_BYTES;
    static HEADER_MAXSIZE = 2 + 1 + this.TRUNCATED_HASHLENGTH_IN_BYTES * 2;
    static TOKEN_OVERHEAD = 48;   // 16B IV + 32B HMAC
    static AES128_BLOCKSIZE = 16;

    // Largest plaintext payload carried by one link data packet.
    // Reference: RNS/Link.py MDU.
    static LINK_MDU = Math.floor(
        (this.MTU - this.IFAC_MIN_SIZE - this.HEADER_MINSIZE - this.TOKEN_OVERHEAD) / this.AES128_BLOCKSIZE,
    ) * this.AES128_BLOCKSIZE - 1;

    // Largest payload of one packet addressed to a destination (not a link).
    // Reference: RNS/Reticulum.py MDU and RNS/Packet.py ENCRYPTED_MDU. The
    // identity key size is 512 bits, and the reference subtracts KEYSIZE//16
    // (the ephemeral key share of a single-packet encryption).
    static KEYSIZE_IN_BITS = 512;
    static PACKET_MDU = this.MTU - this.HEADER_MAXSIZE - this.IFAC_MIN_SIZE;
    static PACKET_ENCRYPTED_MDU = Math.floor(
        (this.PACKET_MDU - this.TOKEN_OVERHEAD - this.KEYSIZE_IN_BITS / 16) / this.AES128_BLOCKSIZE,
    ) * this.AES128_BLOCKSIZE - 1;

}

export default Constants;
