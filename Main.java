import java.util.*;

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
        byte[] expected = HexFormat.of().parseHex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        return new TestResult(name, result, expected);
    }

    private static void runAllTests() {
        // TODO dynamic testing based off input in ./tests/*
        int numPassed = 0;
        int totalTests = 0;
        
        totalTests++;
        TestResult test1 = exampleTest();
        if ( test1.passed() ) {
            numPassed++;
        }
        System.out.println(test1.toString());

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
