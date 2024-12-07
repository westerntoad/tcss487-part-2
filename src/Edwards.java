import java.math.BigInteger;

/**
 * Arithmetic on Edwards elliptic curves.
 *
 * @author  Christian Bonnalie
 * @author  Abraham Engebretson
 * @author  Ethan Somdahl
 * @version Autumn 2024
 */
public class Edwards {

    /**
        * The prime modulus p of the finite field F_p
     */
    private static final BigInteger CONSTANT_P =
            BigInteger.TWO.pow(256).subtract(BigInteger.valueOf(189));

    /**
     * The curve equation coefficient d in the equation
     */
    private static final BigInteger CONSTANT_D =
            BigInteger.valueOf(15343);

    /**
     * The order r of the base point G on the curve
     */
    private static final BigInteger CONSTANT_R =
            BigInteger.TWO.pow(254).subtract(new BigInteger("87175310462106073678594642380840586067"));

    /**
     * Create an instance of the default curve NUMS-256.
     */
    public Edwards() { /* ... */ }

    /**
     * Get the order r.
     * @return R
     */
    public static BigInteger getR() {
        return CONSTANT_R;
    }

    public static BigInteger getP() {
        return CONSTANT_P;
    }

    /**
     * Determine if a given affine coordinate pair P = (x, y)
     * defines a point on the curve.
     *
     * @param x x-coordinate of presumed point on the curve
     * @param y y-coordinate of presumed point on the curve
     * @return whether P is really a point on the curve
     */
    public boolean isPoint(BigInteger x, BigInteger y) {

        //x^2 + y^2
        BigInteger left = (x.multiply(x)).add(y.multiply(y)).mod(CONSTANT_P);
        //1 + dx^2y^2
        BigInteger right = BigInteger.ONE.add(CONSTANT_D.multiply(x.multiply(x)).multiply(y.multiply(y))).mod(CONSTANT_P);

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
        return getPoint(y0, false);
    }
    /**
     * Create a point from its y-coordinate and
     * the least significant bit (LSB) of its x-coordinate.
     *
     * @param y the y-coordinate of the desired point
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
        return new Point(x, y);
    }

    /**
     * Compute the square root of a given value v mod p.
     *
     * @param v     the value to take the square root of
     * @param p     the modulus
     * @param lsb   the least significant bit
     * @return      the square root if it exists, null otherwise
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

        /**
         * Display a human-readable representation of this curve.
         *
         * @return a string of form "E: x^2 + y^2 = 1 + d*x^2*y^2 mod p"
         * where E is a suitable curve name (e.g. NUMS ed-256-mers*),
         * d is the actual curve equation coefficient defining this curve,
         * and p is the order of the underlying finite field F_p.
         */
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

        /**
         * Create a copy of the neutral element on this curve.
         */
        public Point() {
            this.x = BigInteger.ZERO;
            this.y = BigInteger.ONE;
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
        }
        /**
         * Determine if this point is the neutral element O on the curve.
         *
         * @return true iff this point is O
         */
        public boolean isZero() {
            return this.x.equals(BigInteger.ZERO) && this.y.equals(BigInteger.ONE);
        }

        /**
         * Determine if a given point P stands for
         * the same point on the curve as this.
         *
         * @param P a point (presumably on the same curve as this)
         * @return true iff P stands for the same point as this
         */
        public boolean equals(Point P) {
            return this.x.equals(P.x) && this.y.equals(P.y);
        }

        /**
         * Given a point P = (x, y) on the curve,
         * return its opposite -P = (-x, y).
         *
         * @return -P
         */
        public Point negate() {
            return new Point(this.x.negate(), this.y);
        }
        /**
         * Add two given points on the curve, this and P.
         *
         * @param P a point on the curve
         * @return this + P
         */
        public Point add(Point P) {

            if (this.isZero()) return P;
            if (P.isZero()) return this;

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

            Point V = new Point();
            m = m.mod(CONSTANT_R);

            for (int i = m.bitLength() - 1; i >= 0; i--) {
                V = V.add(V);
                if (m.testBit(i)) {
                    V = V.add(this);
                }
            }

            return V;

        }

        /**
         * Display a human-readable representation of this point.
         *
         * @return a string of form "(x, y)" where x and y are
         * the coordinates of this point
         */
        public String toString() {
            return String.format("(%s, %s)", this.x, this.y);
        }
    }
}
