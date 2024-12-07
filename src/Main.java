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

    private static final int R_BYTES = (Edwards.getR().bitLength() + 7) >> 3;

    private static final String HELP_MESSAGE = """
            Commands:
            keygen <passphrase> <output file>
            encrypt <public key file> <message file> <output file>
            decrypt <passphrase> <input file> <output file>
            sign <passphrase> <message file> <output file> // Changed to passphrase first, then message file
            verify <message file> <signature file> <public key file>

            ~ EXTRA CREDIT ~
            encrypt-sign <passphrase> <public key file> <message file> <output file>
            decrypt-verify <passphrase> <public key file> <input file> <output file>
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
        byte[] output = sponge.squeeze(R_BYTES << 1);
        // create a BigInteger from it, reduce this value mod r.
        return new BigInteger(output).mod(Edwards.getR());
    }

    private static byte[] keygen(byte[] passphrase) {
        BigInteger s = generatePrivateKey(passphrase);
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

        byte[] xBytes = V.x.toByteArray();
        byte[] yBytes = V.y.toByteArray();
        /* debug */ System.out.println(HEXF.formatHex(yBytes));
        byte[] out = new byte[64];
        for (int i = 0; i < 32; i++) {
            out[i] = xBytes[i];
        }
        for (int i = 0; i < 32; i++) {
            out[i + 32] = yBytes[i];
        }

        return out;
    }

    private static byte[] encrypt(byte[] message, byte[] publicKey) {
        /* debug */ System.out.println(HEXF.formatHex(publicKey));
        byte[] VyBytes = new byte[33];
        for (int i = 0; i < 32; i++) {
            VyBytes[i + 1] = publicKey[i + 32];
        }
        /* debug */ System.out.println(HEXF.formatHex(VyBytes));
        BigInteger Vy = new BigInteger(VyBytes);

        // create point V from public key
        Edwards instance = new Edwards();
        Edwards.Point V = instance.getPoint(Vy, Vy.testBit(0));

        // generate random k mod r
        var k = new BigInteger(new SecureRandom().generateSeed(R_BYTES << 1)).mod(Edwards.getR());

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
        byte[] stream = shake128.squeeze(message.length);
        byte[] c = new byte[message.length];
        for (int i = 0; i < message.length; i++) {
            c[i] = (byte) (message[i] ^ stream[i]);
        }

        // init sha3-256, absorb ka and c, extract 256-bit t
        SHA3SHAKE sha256 = new SHA3SHAKE();
        sha256.init(256);
        sha256.absorb(ka);
        sha256.absorb(c);
        byte[] t = sha256.squeeze(32);

        // Z.x, Z.y, c, t
        byte[] ZxBytes = Z.x.toByteArray();
        byte[] ZyBytes = Z.y.toByteArray();
        /* debug */ System.out.println(HEXF.formatHex(ZyBytes));
        // /* debug */ System.out.println(Z.y);
        // /* debug */ System.out.println(Z);
        byte[] out = new byte[ZxBytes.length + ZyBytes.length + c.length + t.length];

        for (int i = 0; i < 32; i++) {
            out[i] = ZxBytes[i];
        }
        for (int i = 0; i < 32; i++) {
            out[i + 32] = ZyBytes[i];
        }
        for (int i = 0; i < c.length; i++) {
            out[i + 64] = c[i];
        }
        for (int i = 0; i < 32; i++) {
            out[i + 64 + c.length] = t[i];
        }

        return out;
    }

    /**
     * Decrypt a message using a passphrase.
     *
     * @param passphrase    the passphrase to decrypt the message
     * @param inputDir      the input directory for the encrypted message
     * @param outputDir     the output directory for the decrypted message
     */
    private static byte[] decrypt(byte[] encrypted, String passphrase) {
        // recompute the private key s
        BigInteger s = generatePrivateKey(passphrase.getBytes());

        byte[] ZyBytes = new byte[33];
        byte[] t = new byte[32];
        byte[] c = new byte[encrypted.length - 96];
        for (int i = 0; i < 32; i++) {
            ZyBytes[i + 1] = encrypted[i + 32];
        }
        for (int i = 0; i < c.length; i++) {
            c[i] = encrypted[i + 64];
        }
        for (int i = 0; i < t.length; i++) {
            t[i] = encrypted[i + 64 + c.length];
        }

        // create point Z from input
        BigInteger Zy = new BigInteger(ZyBytes);
        Edwards instance = new Edwards();
        Edwards.Point Z = instance.getPoint(Zy, Zy.testBit(0));
        /* debug */ System.out.println(HEXF.formatHex(ZyBytes));
        // /* debug */ System.out.println(Z.y);
        // /* debug */ System.out.println(Z);

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

        return c;
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
        byte[] hBytes = h.toByteArray(); // always 32 bytes
        byte[] zBytes = z.toByteArray(); // always 32 bytes
        byte[] signature = new byte[64];
        for (int i = 0; i < 32; i++) {
            signature[i] = hBytes[i];
        }
        for (int i = 0; i < 32; i++) {
            signature[i + 32] = zBytes[i];
        }
        return signature;
    }

    private static boolean verify(byte[] message, byte[] signature, byte[] publicKey) {
        byte[] hBytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            hBytes[i] = signature[i];
        }
        byte[] zBytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            zBytes[i] = signature[i + 32];
        }
        BigInteger h = new BigInteger(hBytes);
        BigInteger z = new BigInteger(zBytes);

        byte[] VyBytes = new byte[33];
        for (int i = 0; i < 32; i++) {
            VyBytes[i + 1] = publicKey[i + 32];
        }
        BigInteger Vy = new BigInteger(VyBytes);
        Edwards instance = new Edwards();
        Edwards.Point V = instance.getPoint(Vy, Vy.testBit(0));

        Edwards.Point one = instance.gen().mul(z);
        Edwards.Point two = V.mul(h);
        Edwards.Point uPrime = one.add(two);

        SHA3SHAKE sha256 = new SHA3SHAKE();
        sha256.init(256);
        sha256.absorb(uPrime.y.toByteArray());
        sha256.absorb(message);

        byte[] digest = sha256.digest();
        BigInteger hPrime = new BigInteger(digest).mod(Edwards.getR());

        return h.equals(hPrime);
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
     * Generate a key pair from a passphrase.
     * @param passphrase    the passphrase to generate the key pair from
     * @param outputDir     the output directory for the public key
     */
    private static void keygenService(String passphrase, String outputDir) {
        // write public key to file
        try (FileOutputStream fos = new FileOutputStream(outputDir)) {
            fos.write(keygen(passphrase.getBytes()));
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
    private static void encryptService(String publicKeyFile, String messageFile, String outputDir) {
        try (FileOutputStream fos = new FileOutputStream(outputDir)) {
            byte[] message = Files.readAllBytes(Paths.get(messageFile));
            byte[] publicKey = Files.readAllBytes(Paths.get(publicKeyFile));
            fos.write(encrypt(message, publicKey));
        } catch (IOException e) {
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
    private static void decryptService(String passphrase, String inputDir, String outputDir) {
        try (FileOutputStream fos = new FileOutputStream(outputDir)) {
            // read input from file
            byte[] encrypted = Files.readAllBytes(Paths.get(inputDir));
            fos.write(decrypt(encrypted, passphrase));
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
    private static void signService(String messageFile, String passphrase, String outputDir) {
        try (FileOutputStream fos = new FileOutputStream(outputDir)) {
            byte[] signature = sign(passphrase, Files.readAllBytes(Paths.get(messageFile)));
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
    private static void verifyService(String messageFile, String signatureFile, String publicKeyFile) {
        try {
            byte[] message = Files.readAllBytes(Paths.get(messageFile));
            byte[] signature = Files.readAllBytes(Paths.get(signatureFile));
            byte[] publicKey = Files.readAllBytes(Paths.get(publicKeyFile));

            if (verify(message, signature, publicKey)) {
                System.out.println("Signature Verified!");
            } else {
                System.out.println("Signature not verified.");
            }
        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }

    private static void signedEncryptService(String messageFile, String passphrase, String publicKeyFile, String outputDir) {
        try (FileOutputStream fos = new FileOutputStream(outputDir)) {
            byte[] message = Files.readAllBytes(Paths.get(messageFile));
            byte[] publicKey = Files.readAllBytes(Paths.get(publicKeyFile));
            byte[] encrypted = encrypt(message, publicKey);
            byte[] signature = sign(passphrase, message);
            byte[] out = new byte[encrypted.length + signature.length];
            for (int i = 0; i < encrypted.length; i++) {
                out[i] = encrypted[i];
            }
            for (int i = 0; i < signature.length; i++) {
                out[i + encrypted.length] = signature[i];
            }

            fos.write(out);
        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }
    }
    
    private static void signedDecryptService(String inputDir, String publicKeyFile, String passphrase, String outputDir) {
        try (FileOutputStream fos = new FileOutputStream(outputDir)) {
            byte[] publicKey = Files.readAllBytes(Paths.get(publicKeyFile));
            byte[] raw = Files.readAllBytes(Paths.get(inputDir));
            byte[] signature = new byte[64];
            byte[] encrypted = new byte[raw.length - signature.length];
            for (int i = 0; i < encrypted.length; i++) {
                encrypted[i] = raw[i];
            }
            for (int i = 0; i < signature.length; i++) {
                signature[i] = raw[i + encrypted.length];
            }
            System.out.println(HEXF.formatHex(raw));
            byte[] decrypted = decrypt(encrypted, passphrase);

            if (verify(decrypted, signature, publicKey)) {
                System.out.println("Signature Verified!");
                fos.write(decrypted);
            } else {
                System.out.println("Signature not verified.");
            }
        } catch (IOException e) {
            System.out.println("Error: Invalid path to file. Please try again.");
        }

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
                    keygenService(args[1], args[2]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "encrypt":
                if (args.length == 4) {
                    // 0 = "encrypt"
                    // 1 = public key file
                    // 2 = message file
                    // 3 = output file
                    encryptService(args[1], args[2], args[3]);
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
                    decryptService(args[1], args[2], args[3]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
            case "sign":
                if (args.length == 4) {
                    // 0 = "generate"
                    // 1 = file path
                    // 2 = passphrase
                    // 3 = output file
                    signService(args[1], args[2], args[3]);
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
                    verifyService(args[1], args[2], args[3]);
                } else {
                    System.out.println("Error: Invalid number of arguments.");
                }
                break;
                /*
            Commands:
            keygen <passphrase> <output file>
            encrypt <public key file> <message file> <output file>
            decrypt <passphrase> <input file> <output file>
            sign <passphrase> <message file> <output file> // Changed to passphrase first, then message file
            verify <message file> <signature file> <public key file>
            test

            ~ EXTRA CREDIT ~
            encrypt-sign <passphrase> <public key file> <message file> <output file>
            decrypt-verify <passphrase> <public key file> <input file> <output file>
                 */
            case "encrypt-sign":
    //private static void signedEncryptService(String messageFile, String passphrase, String publicKeyFile, String outputDir) {
                // 0 = "encrypt-sign"
                // 1 = passphrase
                // 2 = public key file
                // 3 = message file
                // 4 = output file
                signedEncryptService(args[3], args[1], args[2], args[4]);
                break;
            case "decrypt-verify":
    //private static void signedDecryptionService(String inputDir, String publicKeyFile, String passphrase, String outputDir) {
                // 0 = "decrypt-verify"
                // 1 = passphrase
                // 2 = public key file
                // 3 = input file
                // 4 = output file
                signedDecryptService(args[3], args[2], args[1], args[4]);
                break;
            case "test":
                test();
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
