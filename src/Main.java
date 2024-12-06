import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;

/**
 * Main class for the Edwards elliptic curve.
 *
 * @author  Christian Bonnalie
 * @author  Abraham Engebretson
 * @author  Ethan Somdahl
 * @version Autumn 2024
 */
public class Main {

    /**
     * HexFormat instance for formatting byte arrays to hex strings.
     */
    private static final HexFormat HEXF = HexFormat.of();

    private static final String HELP_MESSAGE = """
            Commands:
            keygen <passphrase> <output file>
            encrypt <public key file> <message> <output file>
            decrypt <passphrase> <input file> <output file>
            generate <file path> <passphrase> <output file>
            verify <message file> <signature file> <public key file>
            """;

    /**
     * Generate a private key from a passphrase.
     *
     * @param passphrase    the passphrase to generate the private key from
     * @return              the private key
     */
    private static BigInteger generatePrivateKey(byte[] passphrase) {
        // init SHAKE-128, absorb passphrase
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(passphrase);
        int rBytes = (Edwards.getR().bitLength() + 7) >> 3;
        byte[] output = sponge.squeeze(rBytes << 1);
        // create a BigInteger from it, reduce this value mod r.
        return new BigInteger(output).mod(Edwards.getR());
    }

    /**
     * Generate a key pair from a passphrase.
     * @param passphrase    the passphrase to generate the key pair from
     * @param outputDir     the output directory for the public key
     */
    private static void generateKeyPair(String passphrase, String outputDir) {
        BigInteger s = generatePrivateKey(passphrase.getBytes());
        // compute V <- sG
        Edwards instance = new Edwards();
        Edwards.Point V = instance.gen().mul(s);

        // if LSB of x of B is 1
        if (V.x.testBit(0)) {
            // replace s by r-s
            s = Edwards.getR().subtract(s).mod(Edwards.getR());
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

    }

    /**
     * Encrypt a message using a public key.
     *
     * @param publicKeyFile the public key file
     * @param message       the message to encrypt
     * @param outputDir     the output directory for the encrypted message
     */
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

    /**
     * Decrypt a message using a passphrase.
     *
     * @param passphrase    the passphrase to decrypt the message
     * @param inputDir      the input directory for the encrypted message
     * @param outputDir     the output directory for the decrypted message
     */
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

    /**
     * Generate a signature for a file using a passphrase.
     *
     * @param filePath      the file path to generate the signature for
     * @param passphrase    the passphrase to generate the signature from
     * @param outputDir     the output directory for the signature
     */
    private static void generateSignature(String filePath, String passphrase, String outputDir) {
        try (FileOutputStream fos = new FileOutputStream(outputDir)) {
            byte[] signature = sign(passphrase, Files.readAllBytes(Paths.get(filePath)));
            fos.write(signature);
        } catch (Exception e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    /**
     * Verify a signature for a file using a public key.
     *
     * @param messageFile   the message file to verify the signature for
     * @param signatureFile the signature file to verify
     * @param publicKeyFile the public key file to verify the signature with
     */
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

            if (!instance.isPoint(V.x, V.y)) {
                System.out.println("Error: Invalid point. Please try again.");
                return;
            }

            Edwards.Point one = instance.gen().mul(z);
            Edwards.Point two = V.mul(h);
            Edwards.Point uPrime = one.add(two);

            if (!instance.isPoint(uPrime.x, uPrime.y)) {
                System.out.println("Error: Invalid point. Please try again.");
                return;
            }

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

            System.out.println();

        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    private static byte[] sign(String passphrase, byte[] message) {
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
        sha256.absorb(message);
        // extract the 256-bit byte array digest
        byte[] digest = sha256.digest();
        // convert to BI and reduce it mod r
        BigInteger h = new BigInteger(digest).mod(Edwards.getR());
        // compute z = (k-h*s) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(Edwards.getR());

        // the signature is the pair (h,z)
        byte[] hBytes = h.toByteArray();
        byte[] zBytes = z.toByteArray();
        byte[] signature = new byte[64];
        for (int i = 0; i < 32; i++) {
            signature[i] = hBytes[i];
        }
        for (int i = 0; i < 32; i++) {
            signature[i + 32] = zBytes[i];
        }
        return signature;

    }

    /*private static void signedEncrypt(String publicKeyFile, String message, String outputDir, String passphrase) {
        // generate signature
        

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

    }*/

    private static void signedDecrypt() {
        // TODO
    }

    private static void test() {

        Edwards e = new Edwards();
        Edwards.Point G = e.gen();
        Edwards.Point neutral = G.mul(BigInteger.ZERO);
        int failed = 0;

        System.out.println("Testing arithmetic properties...");

        // 0 * G = O
        if (!neutral.equals(G.mul(BigInteger.ZERO))) {
            System.out.println("Error: 0 * G != O");
            failed++;
        }

        // 1 * G = G
        if (!G.equals(G.mul(BigInteger.ONE))) {
            System.out.println("Error: 1 * G != G");
            failed++;
        }

        // G + (-G) = O
        if (!neutral.equals(G.add(G.negate()))) {
            System.out.println("Error: G + (-G) != O");
            failed++;
        }

        // 2 * G = G + G
        if (!G.add(G).equals(G.mul(BigInteger.valueOf(2)))) {
            System.out.println("Error: 2 * G != G + G");
            failed++;
        }

        // 4 * G = 2 * (2 * G)
        if (!G.mul(BigInteger.valueOf(4)).equals(
                G.mul(BigInteger.valueOf(2)).mul(BigInteger.valueOf(2)))) {
            System.out.println("Error: 4 * G != 2 * (2 * G)");
            failed++;
        }

        // 4 * G != 0
        if (neutral.equals(G.mul(BigInteger.valueOf(4)))) {
            System.out.println("Error: 4 * G == O");
            failed++;
        }

        // r * G = 0
        if (!neutral.equals(G.mul(Edwards.getR()))) {
            System.out.println("Error: r * G != O");
            failed++;
        }

        for (int i = 0; i < 50; i++) {

            BigInteger k = new BigInteger(new SecureRandom().generateSeed(32)).mod(Edwards.getR());
            BigInteger l = new BigInteger(new SecureRandom().generateSeed(32)).mod(Edwards.getR());
            BigInteger m = new BigInteger(new SecureRandom().generateSeed(32)).mod(Edwards.getR());

            System.out.println("Testing for:\nk = " + k + "\nl = " + l + "\nm = " + m);

            // kG = (k mod r)G
            if (!G.mul(k).equals(G.mul(k.mod(Edwards.getR())))) {
                failed++;
                System.out.println("Error: kG != (k mod r)G");
            }

            // (k+1)G = kG + G
            if (!G.mul(k.add(BigInteger.ONE)).equals(G.mul(k).add(G))) {
                failed++;
                System.out.println("Error: (k+1)G != kG + G");
            }

            // (k + l)G = kG + lG
            if (!G.mul(k.add(l)).equals(G.mul(k).add(G.mul(l)))) {
                failed++;
                System.out.println("Error: (k + l)G != kG + lG");
            }

            // k(lG) = l(kG) = (kl mod r)G
            if (!G.mul(l).mul(k).equals(G.mul(k).mul(l))) {
                failed++;
                System.out.println("Error: k(lG) != l(kG)");
            }

            // kG + (lG + mG) = (kG + lG) + mG
            if (!G.mul(k).add(G.mul(l).add(G.mul(m))).equals(
                    G.mul(m).add(G.mul(k).add(G.mul(l))))) {
                failed++;
                System.out.println("Error: kG + (lG + mG) != (kG + lG) + mG");
            }

        }

        if (failed == 0) System.out.println("All Tests Passed");
        else System.out.println("Failed " + failed + " Tests");

    }

    /**
     * Main method for the Edwards elliptic curve.
     *
     * @param args  the command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println(HELP_MESSAGE);
            return;
        }

        switch (args[0].toLowerCase()) {
            case "keygen":
                if (args.length == 3) {
                    // 0 = "keygen"
                    // 1 = passphrase
                    // 2 = output file
                    generateKeyPair(args[1], args[2]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "encrypt":
                if (args.length == 4) {
                    // 0 = "encrypt"
                    // 1 = public key file
                    // 2 = message
                    // 3 = output file
                    encrypt(args[1], args[2], args[3]);
                } else if (args.length == 5) {
                    // 0 = "encrypt"
                    // 1 = public key file
                    // 2 = message
                    // 3 = output file
                    // 4 = password
                    //signedEncrypt(args[1], args[2], args[3]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "decrypt":
                if (args.length == 4) {
                    // 0 = "decrypt"
                    // 1 = passphrase
                    // 2 = input file
                    // 3 = output file
                    decrypt(args[1], args[2], args[3]);
                } else if (args.length == 5) {
                    // 0 = "decrypt"
                    // 1 = passphrase
                    // 2 = input file
                    // 3 = output file
                    System.out.println("Error: Invalid number of arguments.");
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "generate":
                if (args.length == 4) {
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
                break;
            case "test":
                //test();
                sign("password", new byte[16]);
                break;
            case "help":
                System.out.println(HELP_MESSAGE);
                break;
            default:
                System.out.println("Error: First argument not a valid application feature.");
                break;
        }
    }
}
