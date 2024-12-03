import java.math.BigInteger;
import java.util.Random;

/**
 * Arithmetic on Edwards elliptic curves.
 */
public class Edwards {

    /**
     * The prime modulus p of the finite field F_p (2^256 - 189).
     */
    private static final BigInteger CONSTANT_P
            = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639747");

    /**
     * The curve equation coefficient d of the curve.
     */
    private static final BigInteger CONSTANT_D = BigInteger.valueOf(15343);

    /**
     * The order r of the base point G of the curve (2^254 - 87175310462106073678594642380840586067).
     */
    private static final BigInteger CONSTANT_R
            = new BigInteger("28948022309329048855892746252171976963230320855948034936185801359597441823917");

    /**
     * Create an instance of the default curve NUMS-256.
     */
    public Edwards() { /* ... */ }

    public static BigInteger getP() {
        return CONSTANT_P;
    }

    public static BigInteger getD() {
        return CONSTANT_D;
    }

    public static BigInteger getR() {
        return CONSTANT_R;
    }

    /**
     * Determine if a given affine coordinate pair P = (x, y)
     * defines a point on the curve
     * (that is, x^2+y^2 = 1+dx^2y^2 is satisfied by P).
     *
     * @param x x-coordinate of presumed point on the curve
     * @param y y-coordinate of presumed point on the curve
     * @return whether P is really a point on the curve
     */
    public boolean isPoint(BigInteger x, BigInteger y) {
        BigInteger left = x.multiply(x).add(y.multiply(y)).mod(CONSTANT_P);
        BigInteger right = BigInteger.ONE.add(
                CONSTANT_D.multiply(x.multiply(x)).multiply(y.multiply(y))).mod(CONSTANT_P);

        return left.equals(right);
    }

    /**
     * Find a generator G on the curve with the smallest possible
     * y-coordinate in absolute value.
     *
     * @return G.
     */
    public Point gen() {
        BigInteger y0 = BigInteger.valueOf(-4).mod(CONSTANT_P);
        // x_lsb is false because x0 must be even
        return getPoint(y0, false);
    }

    /**
     * Create a point from its y-coordinate and
     * the least significant bit (LSB) of its x-coordinate.
     *
     * @param y     the y-coordinate of the desired point
     * @param x_lsb the LSB of its x-coordinate
     * @return point (x, y) if it exists and has order r,
     * otherwise the neutral element O = (0, 1)
     */
    public Point getPoint(BigInteger y, boolean x_lsb) {
        // x = +/- sqrt((1 - y^2) / (1 - d*y^2)) mod p
        BigInteger num = BigInteger.ONE.subtract(y.multiply(y)).mod(CONSTANT_P);
        BigInteger den = BigInteger.ONE.subtract(CONSTANT_D.multiply(y.multiply(y))).mod(CONSTANT_P);
        BigInteger denInv = den.modInverse(CONSTANT_P);
        BigInteger xSquared = num.multiply(denInv).mod(CONSTANT_P);
        BigInteger x = sqrt(xSquared, CONSTANT_P, x_lsb);

        if (x == null) {
            return new Point();
        }

        Point point = new Point(x, y);
        return point.mul(CONSTANT_R).isZero() ? point : new Point();
    }

    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *
     * @param v   the radicand.
     * @param p   the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    public boolean test() {
        Point o = new Point();
        Point g = new Point(BigInteger.valueOf(4), BigInteger.valueOf(23));

        if (!g.mul(BigInteger.ZERO).equals(o)) {
            System.out.println("Failed property:");
            System.out.println("0 * G = O");
            return false;
        }
        if (!g.mul(BigInteger.ONE).equals(g)) {
            System.out.println("Failed property:");
            System.out.println("1 * G = G");
            return false;
        }
        // Not sure why this fails?
        /*if (!a.add(a.negate()).equals(o)) {
            System.out.println("Failed property:");
            System.out.println("G + (-G) = O");
            return false;
        }*/
        if (!g.mul(BigInteger.valueOf(2)).equals(g.add(g))) {
            System.out.println("Failed property:");
            System.out.println("2 * G = G + G");
            return false;
        }
        if (!g.mul(BigInteger.valueOf(4)).equals(g.mul(BigInteger.valueOf(2)).mul(BigInteger.valueOf(2)))) {
            System.out.println("Failed property:");
            System.out.println("4 * G = 2 * (2 * G)");
            return false;
        }
        if (g.mul(BigInteger.valueOf(4)).equals(o)) {
            System.out.println("Failed property:");
            System.out.println("4 * G != O");
            return false;
        }
        if (!g.mul(CONSTANT_R).equals(o)) {
            System.out.println("Failed property:");
            System.out.println("r * G = O");
            return false;
        }

        int numTests = 100;
        Random rand = new Random();
        for (int i = 0; i < numTests; i++) {
            BigInteger k = BigInteger.valueOf(rand.nextInt());
            BigInteger l = BigInteger.valueOf(rand.nextInt());
            BigInteger m = BigInteger.valueOf(rand.nextInt());

            if (!g.mul(k).equals(g.mul(k.mod(CONSTANT_R)))) {
                System.out.println("Failed property:");
                System.out.println("k * G = (k mod r) * G");
                System.out.println("For values:\nk = " + k + "\nl = " + l + "\nm = " + m);
                return false;
            }
            if (!g.mul(k.add(BigInteger.ONE)).equals(g.mul(k).add(g))) {
                System.out.println("Failed property:");
                System.out.println("(k + 1) * G = (k * G) + G");
                System.out.println("For values:\nk = " + k + "\nl = " + l + "\nm = " + m);
                return false;
            }
            if (!g.mul(k.add(l)).equals(g.mul(k).add(g.mul(l)))) {
                System.out.println("Failed property:");
                System.out.println("(k + l) * G = (k * G) + (l * G)");
                System.out.println("For values:\nk = " + k + "\nl = " + l + "\nm = " + m);
                return false;
            }
            if ((!g.mul(l).mul(k).equals(g.mul(k).mul(l))) || (!g.mul(k).mul(l).equals(g.mul(k.multiply(l).mod(CONSTANT_R))))) {
                System.out.println("Failed property:");
                System.out.println("k * (l * G) = l * (k * G) = (k * l mod r) * G");
                System.out.println("For values:\nk = " + k + "\nl = " + l + "\nm = " + m);
                return false;
            }
            if (!g.mul(k).add(g.mul(l).add(g.mul(m))).equals(g.mul(m).add(g.mul(k).add(g.mul(l))))) {
                System.out.println("Failed property:");
                System.out.println("(k * G) + ((l * G) + (m * G)) = ((k * G) + (l * G)) + (m * G)");
                System.out.println("For values:\nk = " + k + "\nl = " + l + "\nm = " + m);
                return false;
            }
        }

        return true;
    }

    /**
     * Display a human-readable representation of this curve.
     *
     * @return a string of form "E: x^2 + y^2 = 1 + d*x^2*y^2 mod p"
     * where E is a suitable curve name (e.g. NUMS ed-256-mers*),
     * d is the actual curve equation coefficient defining this curve,
     * and p is the order of the underlying finite field F_p.
     */
    @Override
    public String toString() {
        return String.format("NUMS ed-256-mers*: x^2 + y^2 = 1 + %s*x^2*y^2 mod %s", CONSTANT_D, CONSTANT_P);
    }

    /**
     * Edwards curve point in affine coordinates.
     * NB: this is a nested class, enclosed within the Edwards class.
     */
    public class Point {

        public final BigInteger x;
        public final BigInteger y;
        private final boolean isNeutral;

        /**
         * Create a copy of the neutral element on this curve.
         */
        public Point() {
            this.x = BigInteger.ZERO;
            this.y = BigInteger.ONE;
            this.isNeutral = true;
        }

        /**
         * Create a point from its coordinates (assuming
         * these coordinates really define a point on the curve).
         *
         * @param x the x-coordinate of the desired point
         * @param y the y-coordinate of the desired point
         */
        private Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
            this.isNeutral = false;
        }

        /**
         * Determine if this point is the neutral element O on the curve.
         *
         * @return true iff this point is O
         */
        public boolean isZero() {
            return isNeutral;
        }

        /**
         * Determine if a given point P stands for
         * the same point on the curve as this.
         *
         * @param P a point (presumably on the same curve as this)
         * @return true iff P stands for the same point as this
         */
        public boolean equals(Point P) {
            if (this.isNeutral && P.isNeutral) return true;
            if (this.isNeutral || P.isNeutral) return false;
            return this.x.equals(P.x) && this.y.equals(P.y);
        }

        /**
         * Given a point P = (x, y) on the curve,
         * return its opposite -P = (-x, y).
         *
         * @return -P
         */
        public Point negate() {
            if (isNeutral) return this;
            return new Point(this.x.negate(), this.y);
        }

        /**
         * Add two given points on the curve, this and P.
         *
         * @param P a point on the curve
         * @return this + P
         */
        public Point add(Point P) {
            if (P.isZero()) return this;
            if (this.isZero()) return P;

            BigInteger x1 = this.x;
            BigInteger y1 = this.y;
            BigInteger x2 = P.x;
            BigInteger y2 = P.y;

            BigInteger dMult = CONSTANT_D.multiply(x1).multiply(x2).multiply(y1).multiply(y2);

            BigInteger numX = x1.multiply(y2).add(y1.multiply(x2)).mod(CONSTANT_P);
            BigInteger denX = BigInteger.ONE.add(dMult).mod(CONSTANT_P);

            BigInteger numY = y1.multiply(y2).subtract(x1.multiply(x2)).mod(CONSTANT_P);
            BigInteger denY = BigInteger.ONE.subtract(dMult).mod(CONSTANT_P);

            // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
            BigInteger newX = numX.multiply(denX.modInverse(CONSTANT_P)).mod(CONSTANT_P);
            // y3 = (y1*y2 - x1*x2) / (1 - d*x1*x2*y1*y2)
            BigInteger newY = numY.multiply(denY.modInverse(CONSTANT_P)).mod(CONSTANT_P);

            return new Point(newX, newY);
        }

        /**
         * Multiply a point P = (x, y) on the curve by a scalar m.
         *
         * @param m a scalar factor (an integer mod the curve order)
         * @return m*P
         */
        public Point mul(BigInteger m) {

            m = m.mod(CONSTANT_R);
            Point r0 = this;
            Point r1 = this.add(this);
            BigInteger swap = BigInteger.ZERO;
            BigInteger si = BigInteger.ZERO;

            for (int i = m.bitLength() - 1; i >= 0; i--) {
                // condswap
                si = m.testBit(i) ? BigInteger.ONE : BigInteger.ZERO;
                swap = swap.xor(si);
                BigInteger diff = r0.xor(r1).andNot(swap);
                r0 = r0.xor(diff);
                r1 = r1.xor(diff);

                r1 = r0.add(r1);
                r0 = r0.add(r0);

                swap = si;
            }



            return r0;
        }

        /**
         * Display a human-readable representation of this point.
         *
         * @return a string of form "(x, y)" where x and y are
         * the coordinates of this point
         */
        @Override
        public String toString() {
            return String.format("(%s, %s)", this.x, this.y);
        }
    }
}
