import java.util.*;
import java.io.*;

public class Main {
    
    private static final HexFormat HEXF = HexFormat.of();
    
    private static final String[] SHA3_TEST_PATHS = {
        "tests/sha-3bytetestvectors/SHA3_224ShortMsg.rsp",
        "tests/sha-3bytetestvectors/SHA3_224LongMsg.rsp",
        "tests/sha-3bytetestvectors/SHA3_256ShortMsg.rsp",
        "tests/sha-3bytetestvectors/SHA3_256LongMsg.rsp",
        "tests/sha-3bytetestvectors/SHA3_384ShortMsg.rsp",
        "tests/sha-3bytetestvectors/SHA3_384LongMsg.rsp",
        "tests/sha-3bytetestvectors/SHA3_512LongMsg.rsp",
        "tests/sha-3bytetestvectors/SHA3_512LongMsg.rsp"
    };

    private static List<TestResult> testFromFileSHA3(File file) {
        List<TestResult> results = new ArrayList<TestResult>();

        try {
            Scanner scanner = new Scanner(file);
            String line = scanner.nextLine();

            while (line.length() > 0 && line.charAt(0) != '[') {
                line = scanner.nextLine();
            }
            line = scanner.nextLine();

            int suffix = Integer.valueOf(line.substring(5, 8));

            scanner.nextLine();

            // loop
            while (scanner.hasNextLine()) {
                int messageLength = Integer.valueOf(scanner.nextLine().substring(6));
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
                if ( result.passed() ) { numPassed++; }

                totalTests++;
                if (additionalInfo) { System.out.println(result.toString()); }
            }
        }

        // TODO more test files and suffixes

        if ( numPassed == totalTests ) {
            System.out.println("Passed all tests.");
        } else {
            System.out.println("Passed " + numPassed + " of " + totalTests + " total tests.");
        }
    }

    public static void main(String[] args) {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-t":
                case "--test":
                    runAllTests(false);
                    break;
                default: continue;
            }
        }
    }

}
