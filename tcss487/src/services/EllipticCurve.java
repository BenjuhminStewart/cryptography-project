package services;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;

import services.kmac.KECCAK;

/**
 * @author Benjamin Stewart
 * @author Blake Hamilton
 * @author Paulo Baretto
 */
public class EllipticCurve implements IService {

    public static final BigInteger prime = BigInteger.valueOf(2).pow(521).subtract(BigInteger.valueOf(1));

    public static final Point G = new Point(BigInteger.valueOf(4), false);

    public static final BigInteger r = BigInteger.valueOf(2).pow(519).subtract(
            new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765"));
    public static final BigInteger n = BigInteger.valueOf(4).multiply(r);

    // Generate an elliptic key pair from a given passphrase and write the public
    // key to a file.
    public KeyPair generateKeyPair(byte[] pw, File dest) {
        byte[] s_bytes = KECCAK.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
        BigInteger s = new BigInteger(s_bytes).multiply(BigInteger.valueOf(4));
        Point V = G.multiply(s);

        KeyPair pair = new KeyPair(s, V);

        try {
            pair.writePublicKey(dest);
        } catch (IOException e) {
            System.out.println("Unable to write public key to file");
            help();
        }
        return pair;
    }

    public void encrypt(File data, File key, File dest) {
        Point pubkey;
        try {
            pubkey = Point.readPublicKey(key);
        } catch (Exception e) {
            System.out.println("Invalid public key.");
            help();
            return;
        }

        try {
            byte[] m = Files.readAllBytes(data.toPath());
            Cryptogram zct = schnorrEncrypt(m, pubkey);
            zct.writeCryptogram(dest);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Invalid data, key, or dest ?");
        }
    }

    public void decrypt(File data, byte[] pw, File dest) {
        try {
            Cryptogram gram = Cryptogram.readCryptogram(data);
            byte[] m = schnorrDecrypt(gram, pw);

            // invalid password
            if (m == null) {
                System.out.println("\nInvalid password\n");
            } else {
                write(dest, m);
                System.out.println("\nSuccessfully written to " + dest.getAbsolutePath() + "\n");
            }
        } catch (IOException | ClassNotFoundException e) {
            help();
        }
    }

    public Cryptogram schnorrEncrypt(byte[] m, Point V) {
        // store 512 bits / 64 bytes of random data
        SecureRandom rand = new SecureRandom();
        byte[] k_bytes = new byte[64];
        rand.nextBytes(k_bytes);

        BigInteger k = new BigInteger(k_bytes);
        k = k.multiply(BigInteger.valueOf(4));

        Point W = V.multiply(k);
        Point Z = G.multiply(k);

        // (ke || ka) = KMACXOF256(Wx, "", 1024, "P")
        byte[] ke_ka = KECCAK.KMACXOF256(W.x.toByteArray(), "".getBytes(), 1024, "P".getBytes());
        byte[] ke = Arrays.copyOfRange(ke_ka, 0, ke_ka.length / 2);
        byte[] ka = Arrays.copyOfRange(ke_ka, ke_ka.length / 2, ke_ka.length);

        // c = KMACXOF256(ke, "", |m|, "PKE") XOR m
        byte[] c = KECCAK.KMACXOF256(ke, "".getBytes(), m.length * 8, "PKE".getBytes());
        for (int i = 0; i < m.length; i++)
            c[i] ^= m[i];

        // t = KMACXOF256(ka, m, 512, "PKA")
        byte[] t = KECCAK.KMACXOF256(ka, m, 512, "PKA".getBytes());
        return new Cryptogram(Z, c, t);
    }

    public byte[] schnorrDecrypt(Cryptogram gram, byte[] pw) {
        // s = KMACXOF256(pw, "", 512, "K"); s = 4s
        byte[] s_bytes = KECCAK.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
        BigInteger s = new BigInteger(s_bytes);
        s = s.multiply(BigInteger.valueOf(4));

        // W = s*Z
        Point W = gram.Z.multiply(s);

        // (ke || ka) = KMACXOF256(Wx, "", 1024, "P")
        byte[] ke_ka = KECCAK.KMACXOF256(W.x.toByteArray(), "".getBytes(), 1024, "P".getBytes());
        byte[] ke = Arrays.copyOfRange(ke_ka, 0, ke_ka.length / 2);
        byte[] ka = Arrays.copyOfRange(ke_ka, ke_ka.length / 2, ke_ka.length);

        // m = KMACXOF256(ke, "", |c|, "PKE") XOR c
        byte[] m = KECCAK.KMACXOF256(ke, "".getBytes(), gram.c.length * 8, "PKE".getBytes());
        for (int i = 0; i < m.length; i++)
            m[i] ^= gram.c[i];

        byte[] t_prime = KECCAK.KMACXOF256(ka, m, 512, "PKA".getBytes());

        return Arrays.equals(gram.t, t_prime) ? m : null;

    }

    public Signature genSignature(byte[] m, byte[] pw) {
        // set s
        byte[] s_bytes = KECCAK.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
        BigInteger s = new BigInteger(s_bytes);
        s = s.multiply(BigInteger.valueOf(4));

        // set k
        byte[] k_bytes = KECCAK.KMACXOF256(s.toByteArray(), m, 512, "N".getBytes());
        BigInteger k = new BigInteger(k_bytes);
        k = k.multiply(BigInteger.valueOf(4));

        // set U
        Point U = G.multiply(k);

        // set h
        byte[] h_bytes = KECCAK.KMACXOF256(U.x.toByteArray(), m, 512, "T".getBytes());
        BigInteger h = new BigInteger(s_bytes);

        // set z
        BigInteger z = (k.subtract(h.multiply(s))).mod(r);

        return new Signature(h_bytes, z);
    }

    public boolean isValidSignature(Signature sig, byte[] m, Point V) {
        Point U = (G.multiply(sig.z)).add(V.multiply(new BigInteger(sig.h)));
        byte[] h_prime = KECCAK.KMACXOF256(U.x.toByteArray(), m, 512, "T".getBytes());
        return Arrays.equals(sig.h, h_prime);
    }

    public void help() {
        System.out.println("\n" + "Elliptic Curve Help".toUpperCase() + "\n");
    }

    public String getDescription() {
        return null;
    }

    public void parse(String[] cmds) {
        // base command: 'ec'
        if (cmds.length == 1) {
            help();
            return;
        }
        // flags:

        // -p -> elliptic key pair
        if (cmds[1].equals("-p")) {
            // arguments for an elliptic key pair => passphrase location
            // usage -> ec -p [password] [location to write to]
            // example -> ec -p 1234 C:\Users\...\new_key_location.txt
            if (cmds.length != 4) {
                help();
                return;
            }
            byte[] password = cmds[2].getBytes();
            File file = new File(cmds[3]);

            generateKeyPair(password, file);
            return;
        }

        // -e -> elliptic curve encryption under a given public key file
        else if (cmds[1].equals("-e")) {
            // arguments for ec encryption => file to encrypt, public key file, destination
            // (will be sent to same location as public key file)
            // usage -> ec -e [file to encrypt] [public key file]
            // example -> ec -e C:\Users\...\message.txt C:\Users\...\pk.txt
            if (cmds.length != 4) {
                help();
                return;
            }

            File data = new File(cmds[2]);
            File key = new File(cmds[3]);
            File dest = new File(getDefaultDestination(cmds[2], "ec-encrypted"));
            encrypt(data, key, dest);
            return;
        }
        // -d -> elliptic curve decryption given an ec encrypted file and a password
        else if (cmds[1].equals("-d")) {
            // arguments for ec decryption => encrypted file and a pw
            // usage -> ec -d [encrypted file] [password]
            // example -> ec -d C:\Users\...\ec.txt 1234

            if (cmds.length != 4) {
                help();
                return;
            }

            File data = new File(cmds[2]);
            File dest = new File(getDefaultDestination(cmds[2], "ec-decrypted"));
            byte[] pw = cmds[3].getBytes();
            decrypt(data, pw, dest);
        }

        // -s -> sign a given password and write the signature to a file
        else if (cmds[1].equals("-s")) {
            // arguments for ec signing => file and a pw
            // usage -> ec -s [file] [password]
            // example -> ec -s C:\Users\...\file.txt 1234
        }
        // -v -> verify a given data file and its signature under a public key
        else if (cmds[1].equals("-v")) {
            // arguments for ec verification => data file and its signature
            // usage -> ec -s [data file] [signature]
            // example -> es -d C:\Users\...\df.txt C:\Users\...\sig.txt
        }

        // not a valid sub command
        else {
            help();
        }
    }

}

class Point implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final BigInteger d = BigInteger.valueOf(-376014);
    public static final BigInteger prime = BigInteger.valueOf(2).pow(521).subtract(BigInteger.valueOf(1));
    public static final Point neutral = new Point(BigInteger.ZERO, BigInteger.ONE);

    BigInteger x, y;

    public Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public Point(BigInteger x, boolean lsb) {
        this.x = x;

        // y = +- sqrt((1 - x^2) / (1 + 376014x^2) mod p)

        BigInteger x_2 = x.pow(2).mod(prime);
        BigInteger num = BigInteger.ONE.subtract(x_2);

        BigInteger denom = BigInteger.ONE.add(BigInteger.valueOf(376014).multiply(x_2).mod(prime));

        this.y = sqrt(num.multiply(denom.modInverse(prime)), prime, lsb);
    }

    public Point(Point p) {
        this.x = p.x;
        this.y = p.y;
    }

    public Point opposite() {
        return new Point(x.multiply(BigInteger.valueOf(-1)), y);
    }

    public Point add(Point p) {
        // let x = (a + b) / (1 + d*c*f)
        BigInteger a = x.multiply(p.y);
        BigInteger b = y.multiply(p.x);

        BigInteger c = x.multiply(p.x);
        BigInteger f = y.multiply(p.y);
        BigInteger dcf = d.multiply(c).multiply(f);

        BigInteger num_x = a.add(b);
        BigInteger den_x = (BigInteger.ONE).add(dcf);

        BigInteger new_x = num_x.multiply(den_x.modInverse(prime)).mod(prime);

        // let y = (u - v) / (1 - d*r*s)
        BigInteger u = y.multiply(p.y);
        BigInteger v = x.multiply(p.x);

        BigInteger r = x.multiply(p.x);
        BigInteger s = y.multiply(p.y);
        BigInteger drs = d.multiply(r).multiply(s);

        BigInteger num_y = u.subtract(v);
        BigInteger den_y = (BigInteger.ONE).subtract(drs);

        BigInteger new_y = num_y.multiply(den_y.modInverse(prime)).mod(prime);

        Point new_point = new Point(new_x, new_y);
        return new_point;
    }

    public Point multiply(BigInteger s) {
        // create two new copies of the current instance
        Point P = new Point(this);
        Point V = new Point(this);

        // get information about bitstring of s
        String bits = s.toString(2);
        int k = s.bitLength();

        // do addition
        for (int i = k - 1; i >= 0; i--) {
            V = V.add(V);
            if (bits.charAt(i) == '1') {
                V = V.add(P);
            }
        }
        return V;
    }

    public boolean equals(Point p) {
        if (this == p) {
            return true;
        } else if (x.equals(p.x) && y.equals(p.y)) {
            return true;
        } else {
            return false;
        }
    }

    public void print() {
        System.out.printf("(x: %s, y: %s)", this.x.toString(10), this.y.toString(10));
    }

    // https://mkyong.com/java/how-to-read-and-write-java-object-to-a-file/
    public void writePublicKey(File file) throws FileNotFoundException, IOException {
        FileOutputStream stream = new FileOutputStream(file);
        ObjectOutputStream output = new ObjectOutputStream(stream);

        output.writeObject(this);

        stream.close();
        output.close();
    }

    public static Point readPublicKey(File file) throws FileNotFoundException, IOException, ClassNotFoundException {
        FileInputStream stream = new FileInputStream(file);
        ObjectInputStream input = new ObjectInputStream(stream);

        Point pubkey = (Point) input.readObject();

        stream.close();
        input.close();

        return pubkey;
    }

    /**
     * Compute a square root of v mod p with a specified least significant bit, if
     * such a root exists.
     *
     * @param v   the radicand.
     * @param p   the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     *         if such a root exists, otherwise null.
     */
    public BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
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

}

class KeyPair {

    BigInteger s;
    Point V;

    public KeyPair(BigInteger s, Point V) {
        this.s = s;
        this.V = V;
    }

    // https://mkyong.com/java/how-to-read-and-write-java-object-to-a-file/
    public void writePublicKey(File file) throws FileNotFoundException, IOException {
        FileOutputStream stream = new FileOutputStream(file);
        ObjectOutputStream output = new ObjectOutputStream(stream);

        output.writeObject(this.V);

        stream.close();
        output.close();
    }

    public static Point readPublicKey(File file) throws FileNotFoundException, IOException, ClassNotFoundException {
        FileInputStream stream = new FileInputStream(file);
        ObjectInputStream input = new ObjectInputStream(stream);

        Point pubkey = (Point) input.readObject();

        stream.close();
        input.close();

        return pubkey;
    }

}

class Cryptogram implements Serializable {

    private static final long serialVersionUID = 1L;

    Point Z;
    byte[] c, t;

    public Cryptogram(Point Z, byte[] c, byte[] t) {
        this.Z = Z;
        this.c = c;
        this.t = t;
    }

    public boolean equals(Cryptogram crypt) {
        if (this == crypt) {
            return true;
        } else if (Arrays.equals(c, crypt.c) && Arrays.equals(t, crypt.t) && crypt.Z.equals(Z)) {
            return true;
        } else {
            return false;
        }
    }

    public void writeCryptogram(File file) throws IOException {
        FileOutputStream stream = new FileOutputStream(file);
        ObjectOutputStream output = new ObjectOutputStream(stream);

        output.writeObject(this);

        stream.close();
        output.close();
    }

    public static Cryptogram readCryptogram(File file)
            throws FileNotFoundException, IOException, ClassNotFoundException {
        FileInputStream stream = new FileInputStream(file);
        ObjectInputStream input = new ObjectInputStream(stream);

        Cryptogram gram = (Cryptogram) input.readObject();

        stream.close();
        input.close();

        return gram;
    }
}

class Signature implements Serializable {

    private static final long serialVersionUID = 1L;

    byte[] h;
    BigInteger z;

    public Signature(byte[] h, BigInteger z) {
        this.h = h;
        this.z = z;
    }

    // https://mkyong.com/java/how-to-read-and-write-java-object-to-a-file/
    public void writeSignature(File file) throws FileNotFoundException, IOException {
        FileOutputStream stream = new FileOutputStream(file);
        ObjectOutputStream output = new ObjectOutputStream(stream);

        output.writeObject(this);

        stream.close();
        output.close();
    }

    public static Signature readSignature(File file) throws FileNotFoundException, IOException, ClassNotFoundException {
        FileInputStream stream = new FileInputStream(file);
        ObjectInputStream input = new ObjectInputStream(stream);

        Signature sig = (Signature) input.readObject();

        stream.close();
        input.close();

        return sig;
    }
}