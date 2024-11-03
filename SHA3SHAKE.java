import java.util.Arrays;

public class SHA3SHAKE {

    /**
     * Number of left-rotations used by the Rho step.
     */
    private static final int[] RHO_TATIONS = {
            // constants manually configured from NIST specs
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
    };

    /**
     * Round constants used by the Iota
     */
    private static final long[] ROUND_CONSTANTS = {
            // constants copied directly copied from mjosaarinen/tiny_sha3 .
            // can be computed ourselves using the NIST specification if needed.
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /**
     * Number of rounds to run Keccak-f for each permutation
     */
    private static final int KECCAK_ROUNDS = 24;

    /**
     * Total size, in bits, of the internal state used by Keccak-f
     */
    private static final int STATE_SIZE = 1600;


    /**
     * Capacity, or c, of the sponge construction. Dependent on the suffix.
     */
    private int capacity;

    /**
     * Rate, or r, of the sponge construction. Dependent on the suffix.
     */
    private int rate_bits;

    /**
     * Rate of the sponge construction expressed in bytes.
     */
    private int rate_bytes;

    private int pos;

    /**
     * Internal state used by Keccak-f. Not dependent on the suffix.
     * Note that the state is indexed to a specific bit like so (using variables as
     * defined by the NIST specs):
     *
     * <pre> {@code
     * bit(x, y, z) = state[y][x] & (1 << z)
     * } </pre>
     */
    private long[][] state;

    /**
     * Unused default constructor used by the class.
     */
    public SHA3SHAKE() { }

    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
     *
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bit length = suffix, SHAKE sec level = suffix)
     */
    public void init(int suffix) {
        capacity = 2 * suffix;
        rate_bits = STATE_SIZE - capacity;
        rate_bytes = rate_bits / 8;
        state = new long[5][5];
        pos = 0;
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param pos  initial index to hash from
     * @param len  byte count on the buffer
     */
    public void absorb(byte[] data, int pos, int len) {

        int j = 0;
        for (int i = pos; i < len; i++) {
            int x = (j / 8) % 5;
            int y = (j / 8) / 5;
            int z = (j % 8) * 8;
            state[y][x] ^= (long) (data[i] & 0xFF) << z;
            j++;

            if (j == rate_bytes) {
//                System.out.println("Data to be absorbed:");
//                printState();
//                printLanes();
                keccakf();
                j = 0;
            }
        }

        this.pos = j;
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param len  byte count on the buffer (starting at index 0)
     */
    public void absorb(byte[] data, int len) {
        absorb(data, 0, len);
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     */
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param out hash value buffer
     * @param len desired number of squeezed bytes
     * @return the val buffer containing the desired hash value
     */
    public byte[] squeeze(byte[] out, int len) {
        return new byte[len];
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) {
        byte[] out = new byte[len];
        pad(false);
        keccakf();


        outer:
        for (int numSqueezes = 0; numSqueezes <= len / rate_bytes; numSqueezes++) {
            int squeezedBytes = 0;

            inner:
            for (long[] lane : state) {
                for (long value : lane) {
                    byte[] temp = longToBytes(value);

                    for (int j = temp.length - 1; j >= 0; j--) {
                        if (squeezedBytes >= rate_bytes)
                            break inner;

                        int idx = squeezedBytes + numSqueezes * rate_bytes;
                        if (idx >= out.length)
                            break outer;

                        out[idx] = temp[j];
                        squeezedBytes++;
                    }
                }
            }


            keccakf();
        }

        return out;
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @param out hash value buffer
     * @return the val buffer containing the desired hash value
     */
    public byte[] digest(byte[] out) {
        pad(true);
        keccakf();

        int i = 0;
        for (long[] lane : state) {
            for (long value : lane) {
                byte[] temp = longToBytes(value);

                for (int j = temp.length - 1; j >= 0 && i < out.length; j--) {
                    out[i] = temp[j];
                    i++;
                }
            }
        }

        return out;
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        return digest(new byte[capacity / 16]);
    }

    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X      data to be hashed
     * @param out    hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);
        sponge.absorb(X);
        return sponge.digest();
    }

    /**
     * Compute the streamlined SHAKE-<128,256> on input X with output bit length L.
     *
     * @param suffix desired security level (either 128 or 256)
     * @param X      data to be hashed
     * @param L      desired output length in bits (must be a multiple of 8)
     * @param out    hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);
        sponge.absorb(X);
        return sponge.squeeze(L / 8);
    }

    private void keccakf() {
        for (int r = 0; r < KECCAK_ROUNDS; r++) {
            /* debug */
//            System.out.printf("\nRound #%d", r);

            // -- THETA --
            // hold the xor of all pillars in a buffer
            // conceptually, pillarXors is a buffer of sheets
            long[] pillarXors = new long[5];
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    pillarXors[i] ^= state[j][i];
                }
            }

            // xor relevant sheets with internal state
            for (int i = 0; i < 5; i++) {
                long sheetIdx = pillarXors[(i + 4) % 5] ^ rotL(pillarXors[(i + 1) % 5], 1);
                for (int j = 0; j < 5; j++) {
                    state[j][i] ^= sheetIdx;
                }
            }
//            /* debug */
//            System.out.println("\nAfter Theta");
//            /* debug */
//            printState();

            // -- RHO --
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    state[i][j] = rotL(state[i][j], RHO_TATIONS[i * 5 + j]);
                }
            }
//            /* debug */
//            System.out.println("\nAfter Rho");
//            /* debug */
//            printState();

            // -- PI --
            int x = 0, y = 1, oldX, oldY;
            long temp = state[y][x];
            // in-place implementation. from any starting coordinate,
            // all other coordinates in a slice will be visited once.
            for (int i = 0; i < 23; i++) {
                oldX = x;
                oldY = y;
                y = x;
                x = (x + 3 * oldY) % 5;
                state[oldY][oldX] = state[y][x];
            }
            state[y][x] = temp;

//            /* debug */
//            System.out.println("\nAfter Pi");
//            /* debug */
//            printState();

            // -- CHI --
            long[] buffer = new long[5];
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    buffer[j] = state[i][j];
                }
                for (int j = 0; j < 5; j++) {
                    state[i][j] ^= (~buffer[(j + 1) % 5]) & buffer[(j + 2) % 5];
                }
            }
//            /* debug */
//            System.out.println("\nAfter Chi");
//            /* debug */
//            printState();

            // -- IOTA --
            state[0][0] ^= ROUND_CONSTANTS[r];
//            /* debug */
//            System.out.println("\nAfter Iota");
//            /* debug */
//            printState();
        }
    }

    /**
     * Prints internal state for debugging purposes.
     */
    private void printState() {
        //byte[][][] bytes = new byte[5][5][8];
        //byte[][][] bytes = new byte[5][5][8];
        //ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);

        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                //buffer.putLong(state[i][j]);
                //bytes[i][j] = buffer.array();
                byte[] bytes = longToBytes(state[i][j]);
                for (int k = 0; k < 8; k++) {
                    System.out.printf("%02X ", bytes[7 - k]);
                }
                if ((i + j) % 2 == 1)
                    System.out.println();
            }
        }
        System.out.println();
    }

    /**
     * Prints internal state in the form of lanes for debugging purposes.
     */
    private void printLanes() {
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                System.out.printf("[%d, %d] = %016x%n", j, i, state[i][j]);
            }
        }
    }

    private static void printHex(byte[] data) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : data) {
            hexString.append(String.format("%02X ", b));
        }
        System.out.println(hexString);
    }


    /* ~~~ HELPER BITWISE METHODS ~~~ */

    /**
     * Takes a value and returns it shifted left by a number of bits, with fallen
     * bits wrapped to the front.
     *
     * @param value the value to be rotated.
     * @param shift the number of bits to shift left.
     * @return the value shifted left a number of bits.
     */
    private static long rotL(long value, int shift) {
        shift %= 64; // Ensure shift is within 64-bit range
        return (value << shift) | (value >>> (64 - shift));
    }

    // taken from:
    // https://stackoverflow.com/a/29132118
    public static byte[] longToBytes(long l) {
        byte[] result = new byte[Long.BYTES];
        for (int i = Long.BYTES - 1; i >= 0; i--) {
            result[i] = (byte) (l & 0xFF);
            l >>= Byte.SIZE;
        }
        return result;
    }

    // taken from:
    // https://stackoverflow.com/a/29132118
    public static long bytesToLong(final byte[] b) {
        long result = 0;
        for (int i = 0; i < Long.BYTES; i++) {
            result <<= Byte.SIZE;
            result |= (b[i] & 0xFF);
        }
        return result;
    }

    private void pad(boolean isSHA) {

        long padStart = (isSHA) ? 0x06L : 0x1FL;

        /* coordinates for start of padding */
        int x = (pos / 8) % 5;
        int y = (pos / 8) / 5;
        int z = (pos % 8) * 8;


        if (state[y][x] == 0L && pos == 1) state[y][x] ^= padStart; // empty message edge case
        else state[y][x] ^= padStart << z;

        /* coordinates for end of padding */
        int rateX = ((rate_bytes - 1) / 8) % 5;
        int rateY = ((rate_bytes - 1) / 8) / 5;
        int rateZ = ((rate_bytes - 1) % 8) * 8;

        state[rateY][rateX] ^= 0x80L << rateZ;

//        System.out.println("\nAfter Pad:");
//        printState();
//        printLanes();
    }
}
