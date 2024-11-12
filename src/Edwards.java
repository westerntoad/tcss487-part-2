import java.math.BigInteger;

/**
* Arithmetic on Edwards elliptic curves.
*/
public class Edwards {

    public static final BigInteger CONSTANT_R = BigInteger.TWO.pow(254).subtract(new BigInteger("87175310462106073678594642380840586067"));

    /**
    * Create an instance of the default curve NUMS-256.
    */
    public Edwards() { /* ... */ }

    /**
    * Determine if a given affine coordinate pair P = (x, y)
    * defines a point on the curve.
    *
    * @param x x-coordinate of presumed point on the curve
    * @param y y-coordinate of presumed point on the curve
    * @return whether P is really a point on the curve
    */
    public boolean isPoint(BigInteger x, BigInteger y) {
        // TODO
        return true;
    }

    /**
    * Find a generator G on the curve with the smallest possible
    * y-coordinate in absolute value.
    *
    * @return G.
    */
    public Point gen() {
        // TODO
        return new Point();
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
        // TODO
        return new Point();
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
        // TODO
        return "";
    }

    /**
    * Edwards curve point in affine coordinates.
    * NB: this is a nested class, enclosed within the Edwards class.
    */
    public class Point {

        private static final BigInteger CONSTANT_D = new BigInteger("15343");
        
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
            BigInteger numX = this.x.multiply(P.y).add(this.y.multiply(P.x));
            BigInteger numY = this.y.multiply(P.y).subtract(this.x.multiply(P.x));

            BigInteger denX = BigInteger.ONE.add(CONSTANT_D.multiply(this.x.multiply(P.x.multiply(this.y.multiply(P.y)))));
            BigInteger denY = BigInteger.ONE.subtract(CONSTANT_D.multiply(this.x.multiply(P.x.multiply(this.y.multiply(P.y)))));

            BigInteger outX = numX.multiply(denX.modInverse(CONSTANT_R));
            BigInteger outY = numY.multiply(denY.modInverse(CONSTANT_R));

            return new Point(outX.mod(CONSTANT_R), outY.mod(CONSTANT_R));
        }

        /**
        * Multiply a point P = (x, y) on the curve by a scalar m.
        *
        * @param m a scalar factor (an integer mod the curve order)
        * @return m*P
        */
        public Point mul(BigInteger m) {
            // TODO Optomize this approach to be more efficient
            
            Point out = new Point();
            for (int i = m.bitLength(); i >= 0; i--) {
                out = out.add(out);
                if (m.testBit(i)) {
                    out = out.add(this);
                }
            }

            return out;
        }

        /**
        * Display a human-readable representation of this point.
        *
        * @return a string of form "(x, y)" where x and y are
        * the coordinates of this point
        */
        public String toString() {
            return String.format("(%s, %s)", this.x.toString(), this.y.toString());
        }
    }
}

