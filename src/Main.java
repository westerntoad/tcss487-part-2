import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;

/**
 * @author Christian Bonnalie
 * @author Abraham Engebretson
 * @author Ethan Somdahl
 */
public class Main {

    private static final HexFormat HEXF = HexFormat.of();

    private static final Map<String, String> DEFAULT_PATHS = new HashMap<>();

    static {
        DEFAULT_PATHS.put("keygen", "../public-key.txt");
        DEFAULT_PATHS.put("encrypt", "../encrypted-message.txt");
        DEFAULT_PATHS.put("decrypt", "../decrypted-message.txt");
        DEFAULT_PATHS.put("generate", "../signature.txt");
    }

    private static final String HELP_MESSAGE = """
            Commands:
            keygen <passphrase> [<output file>]
            encrypt <public key file> <message> [<output file>]
            decrypt <passphrase> <input file> [<output file>]
            generate <file path> <passphrase> [<output file>]
            verify <message file> <signature file> <public key file>
            (output files are optional)
            """;

    private static BigInteger generatePrivateKey(byte[] passphrase) {
        // init SHAKE-128, absorb passphrase
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(passphrase);
        // squeeze a 256-bit byte array
        byte[] output = sponge.squeeze(32);
        // create a BigInteger from it, reduce this value mod r.
        return new BigInteger(output).mod(Edwards.getR());
    }

    private static BigInteger generateKeyPair(byte[] passphrase, String outputDir) {


        // generate s from a passphrase
        BigInteger s = generatePrivateKey(passphrase);
        // compute V <- sG
        Edwards instance = new Edwards();
        Edwards.Point V = instance.gen().mul(s);

        // if LSB of x of B is 1
        if (V.x.testBit(0)) {
            // replace s by r-s
            s = Edwards.getR().subtract(s);
            // replace V by -V
            V = V.negate();
        }

        // write public key to file
        try (FileOutputStream fos = new FileOutputStream(outputDir)) {
            fos.write(HEXF.formatHex(V.x.toByteArray()).getBytes());
            fos.write("\n".getBytes());
            fos.write(HEXF.formatHex(V.y.toByteArray()).getBytes());
        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }

        return s;
    }

    private static void encrypt(String publicKeyFile, String message, String outputDir) {
        try {
            byte[] messageBytes = Files.readAllBytes(Paths.get(message));

            // read public key from file
            List<String> publicKeyLines = Files.readAllLines(Paths.get(publicKeyFile));

            if (publicKeyLines.size() != 2) {
                System.out.println("Error: Invalid public key file. Please try again.");
                return;
            }

            BigInteger Vy = new BigInteger(HEXF.parseHex(publicKeyLines.get(1)));

            // create point V from public key
            Edwards instance = new Edwards();
            Edwards.Point V = instance.getPoint(Vy, Vy.testBit(0));

            // generate random k mod r
            int rBytes = (Edwards.getR().bitLength() + 7) >> 3;
            var k = new BigInteger(new SecureRandom().generateSeed(rBytes << 1)).mod(Edwards.getR());

            // compute W = kV and Z = kG
            Edwards.Point W = V.mul(k);
            Edwards.Point Z = instance.gen().mul(k);

            // init SHAKE-256 and absorb the y-coordinate of W
            SHA3SHAKE shake256 = new SHA3SHAKE();
            shake256.init(256);
            shake256.absorb(W.y.toByteArray());

            // squeeze two successive 256-bit byte arrays
            byte[] ka = shake256.squeeze(32);
            byte[] ke = shake256.squeeze(32);

            // init SHAKE-128 and absorb ke
            SHA3SHAKE shake128 = new SHA3SHAKE();
            shake128.init(128);
            shake128.absorb(ke);

            // squeeze the length of the message and xor with the message
            byte[] stream = shake128.squeeze(messageBytes.length);
            byte[] c = new byte[messageBytes.length];
            for (int i = 0; i < messageBytes.length; i++) {
                c[i] = (byte) (messageBytes[i] ^ stream[i]);
            }

            // init sha3-256, absorb ka and c, extract 256-bit t
            SHA3SHAKE sha256 = new SHA3SHAKE();
            sha256.init(256);
            sha256.absorb(ka);
            sha256.absorb(c);
            byte[] t = sha256.squeeze(32);

            try (FileOutputStream fos = new FileOutputStream(outputDir)) {
                // write Z.x and Z.y to file
                fos.write(HEXF.formatHex(Z.x.toByteArray()).getBytes());
                fos.write("\n".getBytes());
                fos.write(HEXF.formatHex(Z.y.toByteArray()).getBytes());
                fos.write("\n".getBytes());
                // write c to file
                fos.write(HEXF.formatHex(c).getBytes());
                fos.write("\n".getBytes());
                // write t to file
                fos.write(HEXF.formatHex(t).getBytes());
            }
        } catch (Exception e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }

    }

    private static void decrypt(String passphrase, String inputDir, String outputDir) {
        // recompute the private key s
        BigInteger s = generatePrivateKey(passphrase.getBytes());

        try {
            // read input from file
            List<String> inputLines = Files.readAllLines(Paths.get(inputDir));
            BigInteger Zx = new BigInteger(HEXF.parseHex(inputLines.get(0)));
            BigInteger Zy = new BigInteger(HEXF.parseHex(inputLines.get(1)));
            byte[] c = HEXF.parseHex(inputLines.get(2));
            byte[] t = HEXF.parseHex(inputLines.get(3));

            // create point Z from input
            Edwards instance = new Edwards();
            Edwards.Point Z = instance.getPoint(Zy, Zy.testBit(0));

            // compute W = sZ
            Edwards.Point W = Z.mul(s);

            // init SHAKE-256 and absorb the y-coordinate of W
            SHA3SHAKE shake256 = new SHA3SHAKE();
            shake256.init(256);
            shake256.absorb(W.y.toByteArray());

            // squeeze two successive 256-bit byte arrays ka and ke
            byte[] ka = shake256.squeeze(32);
            byte[] ke = shake256.squeeze(32);

            SHA3SHAKE sha256 = new SHA3SHAKE();
            sha256.init(256);
            sha256.absorb(ka);
            sha256.absorb(c);

            byte[] tPrime = sha256.squeeze(32);

            SHA3SHAKE shake128 = new SHA3SHAKE();
            shake128.init(128);
            shake128.absorb(ke);
            byte[] stream = shake128.squeeze(c.length);

            for (int i = 0; i < c.length; i++) {
                c[i] ^= stream[i];
            }

            if (!Arrays.equals(t, tPrime)) {
                System.out.println("Error: Invalid message. Please try again.");
                return;
            }

            try (FileOutputStream fos = new FileOutputStream(outputDir)) {
                fos.write(c);
            }
        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    private static void generateSignature(String filePath, String passphrase, String outputDir) {
        // recompute s from the passphrase
        BigInteger s = generatePrivateKey(passphrase.getBytes());

        // generate random k mod r
        int rBytes = (Edwards.getR().bitLength() + 7) >> 3;
        var k = new BigInteger(new SecureRandom().generateSeed(rBytes << 1)).mod(Edwards.getR());

        // compute U = kG
        Edwards instance = new Edwards();
        Edwards.Point U = instance.gen().mul(k);
        // init sha256, absorb Uy and message
        SHA3SHAKE sha256 = new SHA3SHAKE();
        sha256.init(256);
        sha256.absorb(U.y.toByteArray());
        try {
            sha256.absorb(Files.readAllBytes(Paths.get(filePath)));
        } catch (Exception e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
        // extract the 256-bit byte array digest
        byte[] digest = sha256.digest();
        // convert to BI and reduce it mod r
        BigInteger h = new BigInteger(digest).mod(Edwards.getR());
        // compute z = (k-h*s) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(Edwards.getR());

        // the signature is the pair (h,z)
        try (FileOutputStream fos = new FileOutputStream(outputDir)) {
            fos.write(HEXF.formatHex(h.toByteArray()).getBytes());
            fos.write("\n".getBytes());
            fos.write(HEXF.formatHex(z.toByteArray()).getBytes());
        } catch (Exception e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    private static void verifySignature(String messageFile, String signatureFile, String publicKeyFile) {

        try {
            List<String> signatureLines = Files.readAllLines(Paths.get(signatureFile));
            List<String> publicKeyLines = Files.readAllLines(Paths.get(publicKeyFile));
            byte[] message = Files.readAllBytes(Paths.get(messageFile));

            BigInteger h = new BigInteger(HEXF.parseHex(signatureLines.get(0)));
            BigInteger z = new BigInteger(HEXF.parseHex(signatureLines.get(1)));

            BigInteger Vy = new BigInteger(HEXF.parseHex(publicKeyLines.get(1)));
            Edwards instance = new Edwards();
            Edwards.Point V = instance.getPoint(Vy, Vy.testBit(0));

            Edwards.Point uPrime = instance.gen().mul(z).add(V.mul(h));

            SHA3SHAKE sha256 = new SHA3SHAKE();
            sha256.init(256);
            sha256.absorb(uPrime.y.toByteArray());
            sha256.absorb(message);

            byte[] digest = sha256.digest();
            BigInteger hPrime = new BigInteger(digest).mod(Edwards.getR());

            if (h.equals(hPrime)) {
                System.out.println("Signature Verified!");
            } else {
                System.out.println("Signature not verified.");
            }

        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    public static void main(String[] args) {

        switch (args[0].toLowerCase()) {
            case "keygen":
                if (args.length == 2) {
                    // 0 = "keygen"
                    // 1 = passphrase
                    generateKeyPair(args[1].getBytes(), DEFAULT_PATHS.get("keygen"));
                } else if (args.length == 3) {
                    // 0 = "keygen"
                    // 1 = passphrase
                    // 2 = output file
                    generateKeyPair(args[1].getBytes(), args[2]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "encrypt":
                if (args.length == 3) {
                    // 0 = "encrypt"
                    // 1 = public key file
                    // 2 = message
                    encrypt(args[1], args[2], DEFAULT_PATHS.get("encrypt"));
                } else if (args.length == 4) {
                    // 0 = "encrypt"
                    // 1 = public key file
                    // 2 = message
                    // 3 = output file
                    encrypt(args[1], args[2], args[3]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "decrypt":
                if (args.length == 3) {
                    // 0 = "decrypt"
                    // 1 = passphrase
                    // 2 = input file
                    decrypt(args[1], args[2], DEFAULT_PATHS.get("decrypt"));
                } else if (args.length == 4) {
                    // 0 = "decrypt"
                    // 1 = passphrase
                    // 2 = input file
                    // 3 = output file
                    decrypt(args[1], args[2], args[3]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "generate":
                if (args.length == 3) {
                    // 0 = "generate"
                    // 1 = file path
                    // 2 = passphrase
                    generateSignature(args[1], args[2], DEFAULT_PATHS.get("generate"));
                } else if (args.length == 4) {
                    // 0 = "generate"
                    // 1 = file path
                    // 2 = passphrase
                    // 3 = output file
                    generateSignature(args[1], args[2], args[3]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "verify":
                if (args.length == 4) {
                    // 0 = "verify"
                    // 1 = message file
                    // 2 = signature file
                    // 3 = public key file
                    verifySignature(args[1], args[2], args[3]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
            case "help":
                System.out.println(HELP_MESSAGE);
                break;
            default:
                System.out.println("Error: First argument not a valid application feature.");
                break;
        }
    }
}