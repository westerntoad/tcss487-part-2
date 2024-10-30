import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.io.*;

public class Main {

    public static final HexFormat HEXF = HexFormat.of();

    private static final String[] SHA3_TEST_PATHS = {
            "tests/sha-3bytetestvectors/SHA3_224ShortMsg.rsp",
            "tests/sha-3bytetestvectors/SHA3_256ShortMsg.rsp",
            "tests/sha-3bytetestvectors/SHA3_384ShortMsg.rsp",
            "tests/sha-3bytetestvectors/SHA3_512ShortMsg.rsp",
            "tests/sha-3bytetestvectors/SHA3_224LongMsg.rsp",
            "tests/sha-3bytetestvectors/SHA3_256LongMsg.rsp",
            "tests/sha-3bytetestvectors/SHA3_384LongMsg.rsp",
            "tests/sha-3bytetestvectors/SHA3_512LongMsg.rsp"
    };

    private static void sampleTest() {
        //byte[] message = HEXF.parseHex("3286B7A6");
        //byte[] message = HEXF.parseHex("00");
        //System.out.println(Arrays.toString(message));
        //byte[] message = HEXF.parseHex("197b5853");
        //byte[] message = HEXF.parseHex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434aa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        //byte[] message = HEXF.parseHex("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3");
        String a3 = "A3".repeat(200);
        byte[] m2 = HEXF.parseHex(a3);
        byte[] result = SHA3SHAKE.SHA3(256, m2, null);
        //byte[] expected = HEXF.parseHex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        byte[] expected = HEXF.parseHex("79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787");
        String name = "SHA3-" + 256 + " L=" + 1600;
        TestResult tr = new TestResult(name, result, expected);
        System.out.println(tr);

    }

    private static void testSHA256() throws FileNotFoundException {

        int testCount = 0;
        int passedTests = 0;

        String[] paths = {
                "tests/sha-3bytetestvectors/SHA3_256ShortMsg.rsp",
                "tests/sha-3bytetestvectors/SHA3_256LongMsg.rsp"
        };

        ArrayList<Integer> vectorLengths = new ArrayList<>();
        ArrayList<String> vectorMessages = new ArrayList<>();
        ArrayList<String> vectorExpected = new ArrayList<>();
        ArrayList<Integer> failedTests = new ArrayList<>();

        Scanner scanner;
        for (String path : paths) {
            scanner = new Scanner(new File(path));
            while(scanner.hasNextLine()) {
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
        }

        System.out.println(vectorLengths.size() + " tests.");

        testCount = vectorLengths.size();
        ArrayList<TestResult> results = new ArrayList<>();

        for (int i = 0; i < testCount; i++) {
            byte[] message = HEXF.parseHex(vectorMessages.get(i));
            byte[] expected = HEXF.parseHex(vectorExpected.get(i));
            byte[] actual = SHA3SHAKE.SHA3(256, message, null);
            String name = "SHA3-" + 256 + " L=" + vectorLengths.get(i);
            TestResult tr = new TestResult(name, actual, expected);
            if (tr.passed()) passedTests++;
            else failedTests.add(vectorLengths.get(i));
            results.add(tr);
        }

        for (TestResult tr : results) {
            System.out.println(tr);
        }

        System.out.println(passedTests + " of " + testCount + " SHA3-256 tests passed.\n");
        System.out.println("*** TESTS FAILED ***");
        if (failedTests.isEmpty()) System.out.println("None");
        for (Integer length : failedTests) {
            System.out.println("L="+length);
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

    private static void runAllTests(boolean additionalInfo) {
        int numPassed = 0;
        int totalTests = 0;

        for (String path : SHA3_TEST_PATHS) {
            File file = new File(path);
            for (TestResult result : testFromFileSHA3(file)) {
                if (result.passed()) {
                    numPassed++;
                }

                totalTests++;
                if (additionalInfo) {
                    System.out.println(result.toString());
                }
            }
        }

        // TODO more test files and suffixes

        if (numPassed == totalTests) {
            System.out.println("Passed all tests.");
        } else {
            System.out.println("Passed " + numPassed + " of " + totalTests + " total tests.");
        }
    }

    private static void testSHA3Short() {
        int passed = 0;
        int failed = 0;
    }

    public static void main(String[] args) throws FileNotFoundException {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "test":
                    //runAllTests(true);
                    //sampleTest();
                    testSHA256();
                    break;
                default:
                    continue;
            }
        }
    }

}
