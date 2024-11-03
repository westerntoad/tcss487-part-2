import java.util.*;
import java.io.*;

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

    /**
     * Parse a Known Answer Test Vector from a file.
     * @param path                      the path to the test vector file.
     * @return                          the parsed test vector.
     * @throws FileNotFoundException    if the file is not found.
     */
    private static KATVector parseKATVector(String path) throws FileNotFoundException {

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
            KATVector parsedShort = parseKATVector(version.shortPath);
            KATVector parsedLong = parseKATVector(version.longPath);
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



    private static List<TestResult> testFromFileSHA3(File file) {
        List<TestResult> results = new ArrayList<TestResult>();

        try {
            Scanner scanner = new Scanner(file);
            String line = scanner.nextLine();

            while (!line.isEmpty() && line.charAt(0) != '[') {
                line = scanner.nextLine();
            }
            line = scanner.nextLine();

            int suffix = Integer.parseInt(line.substring(5, 8));

            scanner.nextLine();

            // loop
            while (scanner.hasNextLine()) {
                int messageLength = Integer.parseInt(scanner.nextLine().substring(6));
                byte[] message = HEXF.parseHex(scanner.nextLine().substring(6));
                byte[] result = SHA3SHAKE.SHA3(suffix, message, null);
                byte[] expected = HEXF.parseHex(scanner.nextLine().substring(5));
                String name = "SHA3-" + suffix + " L=" + messageLength;
                results.add(new TestResult(name, result, expected));

                scanner.nextLine();
            }
        } catch (FileNotFoundException e) {
            System.err.println("Could not find file to test.");
            e.printStackTrace();
        }

        return results;
    }

    private static void simpleSHAKETest() {
        byte[] message = HEXF.parseHex("afc9ef4e2e46c719120b68a65aa872273d0873fc6ea353859ff6f034443005e6");
        byte[] expected = HEXF.parseHex("45c65255731e3679b4662f55b02bc5d1c8038a1d778fe91144a5c7d3a286c78c54f5213513");
        byte[] actual = SHA3SHAKE.SHAKE(256, message, 296, null);
        String name = "SHAKE-" + 256 + " L=" + 0;
        TestResult tr = new TestResult(name, actual, expected);
        System.out.println(tr);

    }

    private static void testSHAKE() {
        
    }

    public static void main(String[] args) throws FileNotFoundException {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "test":
                    //testSHA3();
                    System.out.println("Testing SHAKE:");
                    simpleSHAKETest();
                    break;
                default:
                    continue;
            }
        }
    }

}
