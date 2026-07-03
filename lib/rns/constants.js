class Constants {

    // length of truncated hashes (128 bits = 16 bytes, matching Python Reticulum)
    static TRUNCATED_HASHLENGTH_IN_BITS = 128;
    static TRUNCATED_HASHLENGTH_IN_BYTES = this.TRUNCATED_HASHLENGTH_IN_BITS / 8;

}

export default Constants;
