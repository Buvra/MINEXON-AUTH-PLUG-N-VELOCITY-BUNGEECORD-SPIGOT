package xyz.kyngs.librelogin.common.database;

import java.sql.Timestamp;
import java.util.Objects;
import java.util.UUID;
import xyz.kyngs.librelogin.api.crypto.HashedPassword;
import xyz.kyngs.librelogin.api.database.User;

public class AuthenticUser
        implements User {
    private final UUID uuid;
    private UUID premiumUUID;
    private HashedPassword hashedPassword;
    private String lastNickname;
    private Timestamp joinDate;
    private Timestamp lastSeen;
    private String secret;
    private String ip;
    private Timestamp lastAuthentication;
    private String lastServer;
    private String email;

    public AuthenticUser(UUID uuid, UUID premiumUUID, HashedPassword hashedPassword, String lastNickname, Timestamp joinDate, Timestamp lastSeen, String secret, String ip, Timestamp lastAuthentication, String lastServer, String email) {
        this.uuid = uuid;
        this.premiumUUID = premiumUUID;
        this.hashedPassword = hashedPassword;
        this.lastNickname = lastNickname;
        this.joinDate = joinDate;
        this.lastSeen = lastSeen;
        this.secret = secret;
        this.ip = ip;
        this.lastAuthentication = lastAuthentication;
        this.lastServer = lastServer;
        this.email = email;
    }

    @Override
    public Timestamp getLastAuthentication() {
        return this.lastAuthentication;
    }

    @Override
    public void setLastAuthentication(Timestamp lastAuthentication) {
        this.lastAuthentication = lastAuthentication;
    }

    @Override
    public Timestamp getJoinDate() {
        return this.joinDate;
    }

    @Override
    public void setJoinDate(Timestamp joinDate) {
        this.joinDate = joinDate;
    }

    @Override
    public Timestamp getLastSeen() {
        return this.lastSeen;
    }

    @Override
    public void setLastSeen(Timestamp lastSeen) {
        this.lastSeen = lastSeen;
    }

    @Override
    public HashedPassword getHashedPassword() {
        return this.hashedPassword;
    }

    @Override
    public void setHashedPassword(HashedPassword hashedPassword) {
        this.hashedPassword = hashedPassword;
    }

    @Override
    public UUID getUuid() {
        return this.uuid;
    }

    @Override
    public UUID getPremiumUUID() {
        return this.premiumUUID;
    }

    @Override
    public void setPremiumUUID(UUID premiumUUID) {
        this.premiumUUID = premiumUUID;
    }

    @Override
    public String getLastNickname() {
        return this.lastNickname;
    }

    @Override
    public void setLastNickname(String lastNickname) {
        this.lastNickname = lastNickname;
    }

    @Override
    public boolean isRegistered() {
        return this.hashedPassword != null;
    }

    @Override
    public boolean autoLoginEnabled() {
        return this.premiumUUID != null;
    }

    @Override
    public String getEmail() {
        return this.email;
    }

    @Override
    public void setEmail(String email) {
        this.email = email;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || this.getClass() != o.getClass()) {
            return false;
        }
        AuthenticUser user = (AuthenticUser)o;
        return this.uuid.equals(user.uuid);
    }

    public int hashCode() {
        return Objects.hash(this.uuid);
    }

    @Override
    public String getSecret() {
        return this.secret;
    }

    @Override
    public void setSecret(String secret) {
        this.secret = secret;
    }

    @Override
    public String getIp() {
        return this.ip;
    }

    @Override
    public void setIp(String ip) {
        this.ip = ip;
    }

    @Override
    public String getLastServer() {
        return this.lastServer;
    }

    @Override
    public void setLastServer(String lastServer) {
        this.lastServer = lastServer;
    }
}