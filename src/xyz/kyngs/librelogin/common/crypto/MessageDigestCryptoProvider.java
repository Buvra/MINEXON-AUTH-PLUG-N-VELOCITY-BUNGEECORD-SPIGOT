package xyz.kyngs.librelogin.common.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import xyz.kyngs.librelogin.api.crypto.CryptoProvider;
import xyz.kyngs.librelogin.api.crypto.HashedPassword;

public class MessageDigestCryptoProvider
        implements CryptoProvider {
    private final SecureRandom random;
    private final MessageDigest sha256;
    private final String identifier;

    public MessageDigestCryptoProvider(String identifier) {
        this(identifier, identifier);
    }

    public MessageDigestCryptoProvider(String identifier, String md) {
        this.identifier = identifier;
        this.random = new SecureRandom();
        try {
            this.sha256 = MessageDigest.getInstance(md);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    protected String randomSalt() {
        byte[] bytes = new byte[16];
        this.random.nextBytes(bytes);
        return String.format("%016x", new BigInteger(1, bytes));
    }

    protected String plainHash(String input) {
        byte[] inputBytes = input.getBytes();
        byte[] hashedBytes = this.sha256.digest(inputBytes);
        return String.format("%064x", new BigInteger(1, hashedBytes));
    }

    @Override
    public HashedPassword createHash(String password) {
        String salt = this.randomSalt();
        String plain = this.plainHash(password);
        String hash = this.plainHash(plain + salt);
        // Use the correct two-argument constructor
        return new HashedPassword(hash, salt);
    }

    @Override
    public boolean matches(String input, HashedPassword password) {
        // Add null check for the HashedPassword object itself as a safeguard
        if (password == null) {
            // System.err.println("WARN: Attempted to match password against a null HashedPassword object.");
            return false; // Cannot match against null
        }
        // Use the correct getter methods
        String salt = password.getSalt();
        String hash = password.getHash();

        // Also check if the stored hash is null or empty
        if (hash == null || hash.isEmpty()) {
             // System.err.println("WARN: Attempted to match password against a null or empty stored hash.");
             return false; // Cannot match against null/empty hash
        }

        // Hash the input password using the same method as createHash
        String hashedInput = salt == null ? this.plainHash(input) : this.plainHash(this.plainHash(input) + salt);

        // Compare the newly hashed input with the stored hash
        return hashedInput.equals(hash);
    }

    @Override
    public String getIdentifier() {
        return this.identifier;
    }
}
