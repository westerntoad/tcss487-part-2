import java.util.*;
import java.io.*;

public class Main {
    
    private static final HexFormat HEXF = HexFormat.of();

    /*private static byte[] readBytes(String path) throws IOException {
        // inspiration for this method was taken from this StackOverflow answer:
        // https://stackoverflow.com/a/326440
        
        return Files.readAllBytes(Paths.get(path));
    }*/

    private static TestResult exampleTest() {
        String name = "SHA3-256 0x00";
        byte[] message = { 0x00 };
        byte[] result = SHA3SHAKE.SHA3(256, message, null);
        byte[] expected = HEXF.parseHex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        return new TestResult(name, result, expected);
    }

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

    private static void runAllTests() {
        int numPassed = 0;
        int totalTests = 0;

        File file = new File("tests/sha-3bytetestvectors/SHA3_256ShortMsg.rsp");
        for (TestResult result : testFromFileSHA3(file)) {
            if ( result.passed() ) { numPassed++; }

            totalTests++;
            System.out.println(result.toString());
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
                    runAllTests();
                    break;
                default: continue;
            }
        }
    }

}
