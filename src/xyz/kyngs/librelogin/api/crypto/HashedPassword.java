package xyz.kyngs.librelogin.api.crypto;

import org.jetbrains.annotations.Nullable;

public class HashedPassword {
    private final String hash;
    private final String salt;

    public HashedPassword(String hash, @Nullable String salt) {
        this.hash = hash;
        this.salt = salt;
    }

    public String getHash() {
        return hash;
    }

    public String getSalt() {
        return salt;
    }

    @Override
    public String toString() {
        return "HashedPassword{hash='" + hash + "', salt='" + salt + "'}";
    }
}
