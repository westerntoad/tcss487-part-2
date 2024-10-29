import java.nio.ByteBuffer;

public class SHA3SHAKE {

    /** Number of left-rotations used by the Rho step. */
    private static final int[] RHO_TATIONS = {
        // constants copied directly copied from mjosaarinen/tiny_sha3 .
        //1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14, 27,
        //41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44, 0

        // constants manually configured from NIST specs
        0,  1,  62, 28, 27,
        36, 44, 6,  55, 20,
        3,  10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2,  61, 56, 14
    };

    private static final int[] PI_OFFSET = initPiOffset();

    /** Round constants used by the Iota */
    private static final long[] ROUND_CONSTANTS = {
        // constants copied directly copied from mjosaarinen/tiny_sha3 .
        // can be computed ourselves using the NIST specification if needed.
        0x0000000000000001l, 0x0000000000008082l, 0x800000000000808al,
        0x8000000080008000l, 0x000000000000808bl, 0x0000000080000001l,
        0x8000000080008081l, 0x8000000000008009l, 0x000000000000008al,
        0x0000000000000088l, 0x0000000080008009l, 0x000000008000000al,
        0x000000008000808bl, 0x800000000000008bl, 0x8000000000008089l,
        0x8000000000008003l, 0x8000000000008002l, 0x8000000000000080l,
        0x000000000000800al, 0x800000008000000al, 0x8000000080008081l,
        0x8000000000008080l, 0x0000000080000001l, 0x8000000080008008l
    };

    /** Number of rounds to run Keccak-f for each permutation */
    private static final int KECCAK_ROUNDS = 24;

    /** Total size, in bits, of the internal state used by Keccak-f */
    private static final int STATE_SIZE = 1600;


    /** Capacity, or c, of the sponge construction. Dependent on the suffix. */
    private int capacity;

    /** Rate, or r, of the sponge construction. Dependent on the suffix. */
    private int rate;

    /**
     * Internal state used by Keccak-f. Not dependent on the suffix.
     * Note that the state is indexed to a specific bit like so (using variables as
     * defined by the NIST specs):
     *
     * <pre> {@code
     * bit(x, y, z) = state[y][x] & (1 <<< z)
     * } </pre>
     */
    private long[][] state;

    /** Unused default constructor used by the class. */
    public SHA3SHAKE() {
        // Not sure why this is needed?
        // Seems like init is doing the job of the constructor.
    }

    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bit length = suffix, SHAKE sec level = suffix)
     */
    public void init(int suffix) {
        capacity = 2 * suffix;
        rate = STATE_SIZE - capacity;
        state = new long[5][5];
    }

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
    public byte[] squeeze(byte[] out, int len) { return new byte[len]; }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) {
        return squeeze(new byte[len], len);
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @param out hash value buffer
     * @return the val buffer containing the desired hash value
     */
    public byte[] digest(byte[] out) {
        return squeeze(out, capacity / 16);
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        return squeeze(capacity / 16);
    }

    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X data to be hashed
     * @param out hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);

        // NOTE: THIS IS PLACEHOLDER CODE. PLEASE REPLACE WITH SOMETHING THAT
        //       ACTUALLY WORKS.
        int blockedData = (X.length / 8) * 8;
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                byte[] lane = new byte[8];
                int k = 0;
                int idx = (i * 40) + (j * 8) + k;
                while ( idx < X.length && k < 8) {
                    if (idx >= blockedData) {
                        lane[k + (8 - (X.length % 8))] = X[idx];
                    } else {
                        lane[k] = X[idx];
                    }
                    // lane[k + Math.max(0, (8 - (X.length % 8)) - blockedData)] = X[idx];
                    k++;
                    idx = (i * 40) + (j * 8) + k; 
                }
                sponge.state[i][j] = bytesToLong(lane);
            }
        }
        sponge.state[3][1] |= 0x80_00_00_00_00_00_00_00l;
        sponge.printState();
        sponge.printLanes();

        sponge.keccakf();
        return sponge.digest();
    }

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
    
    private void keccakf() {
        for (int r = 0; r < KECCAK_ROUNDS; r++) {
        //for (int r = 0; r < 1; r++) {
            /* debug */ System.out.printf("\nRound #%d", r);
            
            // -- THETA --
            // hold the xor of all pillars in a buffer
            // conceptually, pillarXors is a buffer of sheets
            long[] pillarXors = new long[5];
            for (int i = 0; i < 5; i++) {
                //pillarXors[i] = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ^ state[4][i];
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
            /* debug */ System.out.println("\nAfter Theta");
            /* debug */ printState();

            // -- RHO --
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    state[i][j] = rotL(state[i][j], RHO_TATIONS[i * 5 + j]);
                }
            }
            /* debug */ System.out.println("\nAfter Rho");
            /* debug */ printState();

            // -- PI --
            // REALLY GROSS. TODO: FIX.
            long[][] old = new long[5][];
            for (int i = 0; i < 5; i++) {
                old[i] = state[i].clone();
            }
            for (int i = 0; i < 25; i++) {
                int offsetX = PI_OFFSET[i] % 5;
                int offsetY = PI_OFFSET[i] / 5;
                state[offsetY][offsetX] = old[i / 5][i % 5];
            }

            //long prev = state[0][0];
            //for (int i = 0; i < 25; i++) {
            //    int offsetX = PI_OFFSET[i] % 5;
            //    int offsetY = PI_OFFSET[i] / 5;
            //    long curr = state[offsetY][offsetX];
            //    state[offsetX][offsetY] = prev;
            //    prev = curr;
            //}
            /* debug */ System.out.println("\nAfter Pi");
            /* debug */ printState();

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
            /* debug */ System.out.println("\nAfter Chi");
            /* debug */ printState();

            // -- IOTA --
            state[0][0] ^= ROUND_CONSTANTS[r];
            /* debug */ System.out.println("\nAfter Iota");
            /* debug */ printState();
        }
    }

    /** Prints internal state for debugging purposes. */
    private void printState() {
        //byte[][][] bytes = new byte[5][5][8];
        //ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);

        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                //buffer.putLong(state[i][j]);
                //bytes[i][j] = buffer.array();
                byte[] bytes = longToBytes(state[i][j]);
                for (int k = 0; k < 8; k++) {
                    System.out.print(String.format("%02X ", bytes[7 - k]));
                }
                if ( (i + j) % 2 == 1 )
                    System.out.println();
            }
        }
        System.out.println();
    }

    /** Prints internal state in the form of lanes for debugging purposes. */
    private void printLanes() {
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                System.out.println(String.format("[%d, %d] = %016x", j, i, state[i][j]));
            }
        }
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
            result[i] = (byte)(l & 0xFF);
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

    private static int[] initPiOffset() {
        int[] offsets = new int[25];
        for (int i = 0; i < 25; i++) {
            int x = i % 5;
            int y = i / 5;
            
            // /* debug */ System.out.printf("(x=%d, y=%d) => (x=%d, y=%d)\n", x, y, (x + 3 * y) % 5, x);
            offsets[((x + 3 * y) % 5) + 5 * x] = i;
        }

        return offsets;
    }
}
