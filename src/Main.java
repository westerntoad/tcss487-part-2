import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;

/**
 *
 * @author Christian Bonnalie
 * @author Abraham Engebretson
 * @author Ethan Somdahl
 */
public class Main {

    public static final HexFormat HEXF = HexFormat.of();

    private static BigInteger generateKeyPair(byte[] passphrase, String outputDir) {

        if (outputDir == null) {
            outputDir = "../public-key.txt";
        }

        // init SHAKE-128, absorb passphrase
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(passphrase);

        // squeeze a 256-bit byte array
        byte[] output = sponge.squeeze(32);

        // create a BigInteger from it, reduce this value mod r.
        BigInteger s = new BigInteger(output).mod(Edwards.getR());
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
            Edwards.Point V = instance.getPoint(Vy, false);

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
        BigInteger s = generateKeyPair(passphrase.getBytes(), null);

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

    public static void main(String[] args) {

        switch (args[0].toLowerCase()) {
            case "keygen":
                if (args.length == 2) {
                    // 0 = "keygen"
                    // 1 = passphrase
                    generateKeyPair(args[1].getBytes(), null);
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
                    encrypt(args[1], args[2], "../encrypted-message.txt");
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
                    decrypt(args[1], args[2], "../decrypted-message.txt");
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
            default:
                System.out.println("Error: First argument not a valid application feature.");
                break;
        }
    }
}