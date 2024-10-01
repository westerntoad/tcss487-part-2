public class SHA3SHAKE {

    public SHA3SHAKE() {}

    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bit length = suffix, SHAKE sec level = suffix)
     */
    public void init(int suffix) { /* … */ }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param pos initial index to hash from
     * @param len byte count on the buffer
     */
    public void absorb(byte[] data, int pos, int len) { /* … */ }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param len byte count on the buffer (starting at index 0)
     */
    public void absorb(byte[] data, int len) { /* … */ }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     */
    public void absorb(byte[] data) { /* … */ }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param out hash value buffer
     * @param len desired number of squeezed bytes
     * @return the val buffer containing the desired hash value
     */
    public byte[] squeeze(byte[] out, int len) { return new byte[0]; }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) { return new byte[0]; }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @param out hash value buffer
     * @return the val buffer containing the desired hash value
     */
    public byte[] digest(byte[] out) { return new byte[0]; }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() { return new byte[0]; }

    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X data to be hashed
     * @param out hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) { return new byte[suffix / 8]; }

    /**
     * Compute the streamlined SHAKE-<128,256> on input X with output bit length L.
     *
     * @param suffix desired security level (either 128 or 256)
     * @param X data to be hashed
     * @param L desired output length in bits (must be a multiple of 8)
     * @param out hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) { return new byte[0]; }

}
