import java.util.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class Main {

    /**
     * HexFormat object to parse and format hex strings.
     */
    public static final HexFormat HEXF = HexFormat.of();

    /**
     * Enum to represent the different SHA3 versions.
     * Each version has a bit-length, and a path to the test vectors.
     */
    private enum SHAVersion {
        SHA224(224),
        SHA256(256),
        SHA384(384),
        SHA512(512);

        private final int bits;
        private final String shortPath;
        private final String longPath;
        private final String montePath;

        SHAVersion(int bits) {
            this.bits = bits;
            shortPath = SHAVectorPaths.get(bits)[0];
            longPath = SHAVectorPaths.get(bits)[1];
            montePath = SHAVectorPaths.get(bits)[2];
        }
    }

    private enum SHAKEVersion {
        SHAKE128(128),
        SHAKE256(256);

        private final int bits;
        private final String shortPath;
        private final String longPath;
        private final String montePath;
        private final String variablePath;

        SHAKEVersion(int bits) {
            this.bits = bits;
            shortPath = SHAKEVectorPaths.get(bits)[0];
            longPath = SHAKEVectorPaths.get(bits)[1];
            montePath = SHAKEVectorPaths.get(bits)[2];
            variablePath = SHAKEVectorPaths.get(bits)[3];
        }
    }

    /**
     * Class to represent a Known Answer Test Vector.
     * Each vector has a list of message lengths, messages, and expected message digests.
     */
    private record KATVector(List<Integer> lengths, List<String> messages, List<String> expected) {
    }

    /**
     * Class to represent a Monte Carlo Test Vector.
     * Each vector has a seed and a list of message digests.
     */
    private record MonteVector(String seed, List<String> messageDigests) {
    }

    /**
     * Map to store the paths to the SHA3 test vectors.
     */
    private static final Map<Integer, String[]> SHAVectorPaths = Map.of(
            224, new String[]{
                    "tests/sha-3bytetestvectors/SHA3_224ShortMsg.rsp",
                    "tests/sha-3bytetestvectors/SHA3_224LongMsg.rsp",
                    "tests/sha-3bytetestvectors/SHA3_224Monte.rsp"
            },
            256, new String[]{
                    "tests/sha-3bytetestvectors/SHA3_256ShortMsg.rsp",
                    "tests/sha-3bytetestvectors/SHA3_256LongMsg.rsp",
                    "tests/sha-3bytetestvectors/SHA3_256Monte.rsp"
            },
            384, new String[]{
                    "tests/sha-3bytetestvectors/SHA3_384ShortMsg.rsp",
                    "tests/sha-3bytetestvectors/SHA3_384LongMsg.rsp",
                    "tests/sha-3bytetestvectors/SHA3_384Monte.rsp"
            },
            512, new String[]{
                    "tests/sha-3bytetestvectors/SHA3_512ShortMsg.rsp",
                    "tests/sha-3bytetestvectors/SHA3_512LongMsg.rsp",
                    "tests/sha-3bytetestvectors/SHA3_512Monte.rsp"
            }
    );

    private static final Map<Integer, String[]> SHAKEVectorPaths = Map.of(
            128, new String[]{
                    "tests/shakebytetestvectors/SHAKE128ShortMsg.rsp",
                    "tests/shakebytetestvectors/SHAKE128LongMsg.rsp",
                    "tests/shakebytetestvectors/SHAKE128Monte.rsp",
                    "tests/shakebytetestvectors/SHAKE128VariableOut.rsp"
            },
            256, new String[] {
                    "tests/shakebytetestvectors/SHAKE256ShortMsg.rsp",
                    "tests/shakebytetestvectors/SHAKE256LongMsg.rsp",
                    "tests/shakebytetestvectors/SHAKE256Monte.rsp",
                    "tests/shakebytetestvectors/SHAKE256VariableOut.rsp"
            }
    );


    /**
     * Parse a Known Answer Test Vector from a file.
     * @param path                      the path to the test vector file.
     * @return                          the parsed test vector.
     * @throws FileNotFoundException    if the file is not found.
     */
    private static KATVector parseSHA3KATVector(String path) throws FileNotFoundException {

        List<Integer> vectorLengths = new ArrayList<>();
        List<String> vectorMessages = new ArrayList<>();
        List<String> vectorExpected = new ArrayList<>();

        Scanner scanner;
        scanner = new Scanner(new File(path));
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().trim();
            if (line.startsWith("Len")) {
                int len = Integer.parseInt(line.split(" = ")[1]);
                vectorLengths.add(len);
            } else if (line.startsWith("Msg")) {
                String message = line.split(" = ")[1];
                vectorMessages.add(message);
            } else if (line.startsWith("MD")) {
                String md = line.split(" = ")[1];
                vectorExpected.add(md);
            }
        }
        scanner.close();
        return new KATVector(vectorLengths, vectorMessages, vectorExpected);
    }

    private static KATVector parseSHAKEKATVector(String path) throws FileNotFoundException {

        List<Integer> vectorLengths = new ArrayList<>();
        List<String> vectorMessages = new ArrayList<>();
        List<String> vectorExpected = new ArrayList<>();
        List<String> outputLengths = new ArrayList<>();

        Scanner scanner;
        scanner = new Scanner(new File(path));
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().trim();
            if (line.startsWith("Len")) {
                int len = Integer.parseInt(line.split(" = ")[1]);
                vectorLengths.add(len);
            } else if (line.startsWith("Msg")) {
                String message = line.split(" = ")[1];
                vectorMessages.add(message);
            } else if (line.startsWith("MD")) {
                String md = line.split(" = ")[1];
                vectorExpected.add(md);
            }
        }
        scanner.close();
        return new KATVector(vectorLengths, vectorMessages, vectorExpected);
    }

    /**
     * Parse a Monte Carlo Test Vector from a file.
     * @param path                      the path to the test vector file.
     * @return                          the parsed test vector.
     * @throws FileNotFoundException    if the file is not found.
     */
    private static MonteVector parseMonteVector(String path) throws FileNotFoundException {

        List<String> seed = new ArrayList<>();
        List<String> messageDigests = new ArrayList<>();

        Scanner scanner;
        scanner = new Scanner(new File(path));
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().trim();
            if (line.startsWith("Seed")) {
                seed.add(line.split(" = ")[1]);
            } else if (line.startsWith("MD")) {
                messageDigests.add(line.split(" = ")[1]);
            }
        }
        scanner.close();

        return new MonteVector(seed.get(0), messageDigests);
    }

    
    /**
     * Run the SHA3 Known Answer Tests and Monte Carlo Tests.
     * @throws FileNotFoundException if the test vector files are not found.
     */
    private static void testSHA3() throws FileNotFoundException {
        for (SHAVersion version : SHAVersion.values()) {
            KATVector parsedShort = parseSHA3KATVector(version.shortPath);
            KATVector parsedLong = parseSHA3KATVector(version.longPath);
            MonteVector parsedMonte = parseMonteVector(version.montePath);

            System.out.println("////////// SHA3-" + version.bits + " TESTS //////////");
            runSHA3KAT(version.bits, parsedShort);
            runSHA3KAT(version.bits, parsedLong);
            runSHA3Monte(version.bits, parsedMonte);
            System.out.println();

        }
    }

    /**
     * Run the SHA3 Known Answer Tests for a given suffix and vector.
     * @param suffix the bit-length of the SHA3 version.
     * @param vector the test vector to run.
     */
    private static void runSHA3KAT(int suffix, KATVector vector) {
        List<Integer> failedTests = new ArrayList<>();
        int testCount = vector.lengths.size();
        int passedTests = 0;

        Long start = System.nanoTime();
        for (int i = 0; i < testCount; i++) {
            byte[] message = HEXF.parseHex(vector.messages.get(i));
            byte[] expected = HEXF.parseHex(vector.expected.get(i));
            byte[] actual = SHA3SHAKE.SHA3(suffix, message, null);
            String name = "SHA3-" + suffix + " L=" + vector.lengths.get(i);
            TestResult tr = new TestResult(name, actual, expected);
            if (tr.passed()) passedTests++;
            else failedTests.add(vector.lengths.get(i));
        }
        Long end = System.nanoTime();

        double time = (end - start) / 1E6;
        System.out.println(passedTests + " of " + testCount + " SHA3-" + suffix
                + " Known Answer Tests passed in " + time + " milliseconds.");
        if (!failedTests.isEmpty()) System.out.println("**** TESTS FAILED ****");
        for (Integer length : failedTests) {
            System.out.println("L=" + length);
        }
    }

    /**
     * Run the SHA3 Monte Carlo Tests for a given suffix and vector.
     * @param suffix the bit-length of the SHA3 version.
     * @param vector the test vector to run.
     */
    private static void runSHA3Monte(int suffix, MonteVector vector) {
        boolean passed = true;
        String seed = vector.seed;
        List<String> digests = vector.messageDigests;

        Long start = System.nanoTime();
        for (int i = 0; i < digests.size(); i++) {

            byte[] actual = (i == 0) ? HEXF.parseHex(seed) : HEXF.parseHex(digests.get(i - 1));
            for (int j = 0; j < 1000; j++) {
                actual = SHA3SHAKE.SHA3(suffix, actual, null);
            }
            byte[] expected = HEXF.parseHex(digests.get(i));

            String name = "SHA3-" + suffix + " L=" + suffix;
            TestResult tr = new TestResult(name, actual, expected);

            if (!tr.passed()) {
                System.out.println("Monte " + suffix + " failed at checkpoint #" + i);
                passed = false;
                break;
            }
        }
        Long end = System.nanoTime();

        if (passed) {
            double timeMillis = (end - start) / 1E6;
            double timeSeconds = (end - start) / 1E9;
            System.out.println("SHA3-" + suffix + " Monte test passed in " + timeMillis
                    + " milliseconds (~" + (int) (1_000_000 / timeSeconds) + " tests per second).");
        }
    }



    // private static List<TestResult> testFromFileSHA3(File file) {
    //     List<TestResult> results = new ArrayList<TestResult>();

    //     try {
    //         Scanner scanner = new Scanner(file);
    //         String line = scanner.nextLine();

    //         while (!line.isEmpty() && line.charAt(0) != '[') {
    //             line = scanner.nextLine();
    //         }
    //         line = scanner.nextLine();

    //         int suffix = Integer.parseInt(line.substring(5, 8));

    //         scanner.nextLine();

    //         // loop
    //         while (scanner.hasNextLine()) {
    //             int messageLength = Integer.parseInt(scanner.nextLine().substring(6));
    //             byte[] message = HEXF.parseHex(scanner.nextLine().substring(6));
    //             byte[] result = SHA3SHAKE.SHA3(suffix, message, null);
    //             byte[] expected = HEXF.parseHex(scanner.nextLine().substring(5));
    //             String name = "SHA3-" + suffix + " L=" + messageLength;
    //             results.add(new TestResult(name, result, expected));

    //             scanner.nextLine();
    //         }
    //     } catch (FileNotFoundException e) {
    //         System.err.println("Could not find file to test.");
    //         e.printStackTrace();
    //     }

    //     return results;
    // }

    private static void simpleSHAKETest() {
        byte[] message = HEXF.parseHex("8d8001e2c096f1b88e7c9224a086efd4797fbf74a8033a2d422a2b6b8f6747e4");
        byte[] expected = HEXF.parseHex("2e975f6a8a14f0704d51b13667d8195c219f71e6345696c49fa4b9d08e9225d3d39393425152c97e71dd24601c11abcfa0f12f53c680bd3ae757b8134a9c10d429615869217fdd5885c4db174985703a6d6de94a667eac3023443a8337ae1bc601b76d7d38ec3c34463105f0d3949d78e562a039e4469548b609395de5a4fd43c46ca9fd6ee29ada5efc07d84d553249450dab4a49c483ded250c9338f85cd937ae66bb436f3b4026e859fda1ca571432f3bfc09e7c03ca4d183b741111ca0483d0edabc03feb23b17ee48e844ba2408d9dcfd0139d2e8c7310125aee801c61ab7900d1efc47c078281766f361c5e6111346235e1dc38325666c");
        byte[] actual = SHA3SHAKE.SHAKE(256, message, 2000, null);
        String name = "SHAKE-" + 256 + " L=" + 0;
        TestResult tr = new TestResult(name, actual, expected);
        System.out.println(tr);

    }
    
    private static final void hash(String dir, int suffix) {
        try {
            byte[] contents = Files.readAllBytes(Paths.get(dir));
            byte[] output = SHA3SHAKE.SHA3(suffix, contents, null);
            System.out.println(HEXF.formatHex(output));
        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    private static final void macFromFile(String dir, String pass, int suffix, int length) {
        if (length <= 0) {
            System.out.println("Error: MAC tag lengths must be positive.");
        }
        try {
            byte[] contents = Files.readAllBytes(Paths.get(dir));
            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(suffix);
            sponge.absorb(pass.getBytes());
            sponge.absorb(contents);
            byte[] mac = sponge.squeeze(length);

            System.out.println(HEXF.formatHex(mac));
        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    private static final void encrypt(String dir, String pass) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] contents = Files.readAllBytes(Paths.get(dir));
            /* debug */ System.out.println(contents.length);
            byte[] nonce = new byte[16];
            random.nextBytes(nonce);
            byte[] hashedKey = SHA3SHAKE.SHAKE(128, pass.getBytes(), 128, null);

            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(128);
            sponge.absorb(nonce);
            sponge.absorb(hashedKey);
            byte[] cipher = sponge.squeeze(contents.length);
            ///* debug */ System.out.println(HEXF.formatHex(cipher));

            for (int i = 0; i < contents.length; i++) {
                contents[i] ^= cipher[i];
            }
            
            System.out.println(new String(contents));
            System.out.print(HEXF.formatHex(nonce));
        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    private static final void decrypt(String dir, String pass, byte[] nonce) {
        try {
            byte[] contents = Files.readAllBytes(Paths.get(dir));
            /* debug */ System.out.println(contents.length);
            byte[] hashedKey = SHA3SHAKE.SHAKE(128, pass.getBytes(), 128, null);

            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(128);
            sponge.absorb(nonce);
            sponge.absorb(hashedKey);
            byte[] cipher = sponge.squeeze(contents.length);
            ///* debug */ System.out.println(HEXF.formatHex(cipher));

            for (int i = 0; i < contents.length; i++) {
                contents[i] ^= cipher[i];
            }
            
            System.out.print(new String(contents));
        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    public static void main(String[] args) throws FileNotFoundException {
        switch (args[0].toLowerCase()) {
            case "hash":
                if (args.length == 3) {
                    // # arguments
                    // 0 = "hash"
                    // 1 = security level
                    // 2 = file directory

                    System.out.println(args[1]);
                    if (!args[1].matches("224|256|384|512")) {
                        System.out.println("Error: Invalid security level for hashing function. Implemented security levels include: 224, 256, 384, or 512.");
                    } else {
                        hash(args[2], Integer.valueOf(args[1]));
                    }
                } else if (args.length == 2) {
                    // # arguments
                    // 0 = "hash"
                    // 1 = file directory
                    
                    // default security level is 512
                    hash(args[1], 512);
                } else if (args.length == 1){
                    System.out.println("Error: Please provide path to the file to hash.");
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "mac":
                if (args.length == 5) {
                    // # arguments
                    // 0 = "mac"
                    // 1 = security level
                    // 2 = passkey
                    // 3 = file directory
                    // 4 = number of outputted bits
                    
                    if (!args[1].matches("128|256")) {
                        System.out.println("Error: Invalid security level for Message Authentication Code. Implemented security levels include: 224, 256, 384, or 512.");
                    } else {
                        try {
                            int length = Integer.parseInt(args[4]);
                            int suffix = Integer.parseInt(args[1]);
                            macFromFile(args[3], args[2], suffix, length);
                        } catch (NumberFormatException e) {
                            System.out.println("Error parsing MAC output length.");
                        }
                    }
                } else if (args.length == 4) {
                    // # arguments
                    // 0 = "mac"
                    // 1 = passkey
                    // 2 = file directory
                    // 3 = number of outputted bits
                    
                    // default security level is 256
                    try {
                        int length = Integer.parseInt(args[3]);
                        macFromFile(args[2], args[1], 256, length);
                    } catch (NumberFormatException e) {
                        System.out.println("Error parsing MAC output length.");
                    }
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "encrypt":
                if (args.length == 3) {
                    // # arguments
                    // 0 = "encrypt"
                    // 1 = passphrase
                    // 2 = file directory

                    encrypt(args[2], args[1]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                // DEBUG
                // cipher = 38f2f5c0d9c5
                // nonce = a7bcf3afb8a3fca71de7ab251c018da1
                break;
            case "decrypt":
                if (args.length == 4) {
                    // # arguments
                    // 0 = "decrypt"
                    // 1 = passphrase
                    // 2 = file directory
                    // 3 = random nonce from encryption

                    decrypt(args[2], args[1], HEXF.parseHex(args[3]));
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "test":
                //testSHA3();
                System.out.println("Testing SHAKE:");
                simpleSHAKETest();
                break;
            default:
                System.out.println("Error: First argument not a valid application feature.");
                break;
        }
    }

}
