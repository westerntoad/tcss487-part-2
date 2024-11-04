import java.util.*;

public class TestResult {
    private final String name;
    private final byte[] result;
    private final byte[] expected;
    
    public TestResult(String name, byte[] result, byte[] expected) {
        this.name = name;
        this.result = result;
        this.expected = expected;
    }

    public String name() {
        return this.name;
    }

    public byte[] result() {
        return this.result;
    }
    
    public byte[] expected() {
        return this.expected;
    }

    public boolean passed() {
        return Arrays.equals(this.result, this.expected);
    }

    @Override
    public String toString() {
        if (this.passed()) {
            return "Test " + this.name() + " passed.";
        }

        StringBuilder sb = new StringBuilder();

        sb.append("Test ");
        sb.append(this.name());
        sb.append(" failed.\n");
        sb.append("expected  ");
        sb.append(Main.HEXF.formatHex(this.expected));
        sb.append('\n');
        sb.append("actual    ");
        sb.append(Main.HEXF.formatHex(this.result));
        sb.append('\n');

        return sb.toString();
    }
}
