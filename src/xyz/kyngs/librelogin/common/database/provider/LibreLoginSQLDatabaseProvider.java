package xyz.kyngs.librelogin.common.database.provider;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.jetbrains.annotations.Nullable;
import xyz.kyngs.librelogin.api.crypto.HashedPassword;
import xyz.kyngs.librelogin.api.database.User;
import xyz.kyngs.librelogin.api.database.connector.SQLDatabaseConnector;
import xyz.kyngs.librelogin.common.AuthenticLibreLogin;
import xyz.kyngs.librelogin.common.database.AuthenticDatabaseProvider;
import xyz.kyngs.librelogin.common.database.AuthenticUser;

public abstract class LibreLoginSQLDatabaseProvider
        extends AuthenticDatabaseProvider<SQLDatabaseConnector> {

    private static final String DEFAULT_PROVIDER_KEY = "SHA256";

    public LibreLoginSQLDatabaseProvider(SQLDatabaseConnector connector, AuthenticLibreLogin<?, ?> plugin) {
        super(connector, plugin);
    }

    @Override
    public Collection<User> getByIP(String ip) {
        plugin.reportMainThread();
        return connector.runQuery(connection -> {
            PreparedStatement ps = connection.prepareStatement("SELECT * FROM accounts WHERE ip=?");
            ps.setString(1, ip);
            ResultSet rs = ps.executeQuery();
            List<User> users = new ArrayList<>();
            User u;
            while ((u = getUserFromResult(rs)) != null) {
                users.add(u);
            }
            return users;
        });
    }

    @Override
    public User getByName(String name) {
        plugin.reportMainThread();
        return connector.runQuery(connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "SELECT * FROM accounts WHERE LOWER(realname)=LOWER(?)"
            );
            ps.setString(1, name);
            ResultSet rs = ps.executeQuery();
            return getUserFromResult(rs);
        });
    }

    @Override
    public Collection<User> getAllUsers() {
        plugin.reportMainThread();
        return connector.runQuery(connection -> {
            PreparedStatement ps = connection.prepareStatement("SELECT * FROM accounts");
            ResultSet rs = ps.executeQuery();
            List<User> users = new ArrayList<>();
            User u;
            while ((u = getUserFromResult(rs)) != null) {
                users.add(u);
            }
            return users;
        });
    }

    @Override
    public User getByUUID(UUID uuid) {
        plugin.reportMainThread();
        return connector.runQuery(connection -> {
            PreparedStatement ps = connection.prepareStatement("SELECT * FROM accounts WHERE uuid=?");
            ps.setString(1, uuid.toString());
            ResultSet rs = ps.executeQuery();
            return getUserFromResult(rs);
        });
    }

    @Override
    public User getByPremiumUUID(UUID uuid) {
        plugin.reportMainThread();
        return connector.runQuery(connection -> {
            PreparedStatement ps = connection.prepareStatement("SELECT * FROM accounts WHERE premium_uuid=?");
            ps.setString(1, uuid.toString());
            ResultSet rs = ps.executeQuery();
            return getUserFromResult(rs);
        });
    }

    @Nullable
    private User getUserFromResult(ResultSet rs) throws SQLException {
        if (!rs.next()) return null;
        String currentRealName = rs.getString("realname");

        // --- UUID ---
        String uuidStr = rs.getString("uuid");
        UUID id;
        if (uuidStr == null || uuidStr.isEmpty()) {
             System.err.println("WARN: Missing UUID for user " + currentRealName + ". Cannot load user.");
             return null; // Cannot load user without a UUID string
        }
        try {
            id = UUID.fromString(uuidStr);
        } catch (IllegalArgumentException ex) {
            // Log the specific invalid UUID string
            System.err.println("WARN: Invalid UUID format '" + uuidStr + "' for user " + currentRealName + ". Cannot load user.");
            return null; // Return null if UUID string is invalid
        }

        // --- Premium UUID ---
        UUID premiumUUID = null;
        String premium = rs.getString("premium_uuid");
        if (premium != null && !premium.isEmpty()) {
            try {
                premiumUUID = UUID.fromString(premium);
            } catch (Exception ex) {
                System.err.println("WARN: Invalid premium UUID for user " + currentRealName);
            }
        }

        // --- Password parsing ---
        String raw = rs.getString("password");
        HashedPassword hp = null;
        if (raw != null && !raw.trim().isEmpty()) {
            raw = raw.trim();
            // Expected format: $SHA$<salt>$<hash>
            if (raw.startsWith("$SHA$")) {
                String[] parts = raw.split("\\$", 3); // Limit split to 3 parts: "", "SHA", "<salt>$<hash>"
                // parts[0] is empty string before the first $
                // parts[1] should be "SHA" (or the algorithm name)
                // parts[2] should be "<salt>$<hash>"
                if (parts.length == 3) {
                    String[] saltAndHash = parts[2].split("\\$", 2); // Split the rest into salt and hash
                    if (saltAndHash.length == 2 && !saltAndHash[0].isEmpty() && !saltAndHash[1].isEmpty()) {
                        // parts[1] could be used to store/check the algorithm if needed in the future
                        hp = new HashedPassword(saltAndHash[1], saltAndHash[0]); // hash, salt
                    } else {
                        System.err.println("WARN: Bad password format (salt/hash part) for user " + currentRealName + ". Raw: " + raw);
                    }
                } else {
                    System.err.println("WARN: Bad password format (prefix/split) for user " + currentRealName + ". Raw: " + raw);
                }
            } else if (!raw.isEmpty()) { // Only warn about missing prefix if the field wasn't empty
                System.err.println("WARN: Missing '$SHA$' prefix for user " + currentRealName + ". Raw: " + raw);
            }
            // No warning if raw is null or empty, as this might be a new/unregistered user
        }

        // --- Other fields ---
        Timestamp joined   = rs.getTimestamp("joined");
        Timestamp seen     = rs.getTimestamp("last_seen");
        String secret      = rs.getString("secret");
        String ip          = rs.getString("ip");
        Timestamp lastAuth = rs.getTimestamp("last_authentication");
        String lastSrv     = rs.getString("last_server");
        String email       = rs.getString("email");

        return new AuthenticUser(
                id,
                premiumUUID,
                hp,
                currentRealName,
                joined,
                seen,
                secret,
                ip,
                lastAuth,
                lastSrv,
                email
        );
    }

    @Override
    public void insertUser(User user) {
        plugin.reportMainThread();
        try {
            connector.runQuery(connection -> {
                PreparedStatement ps = connection.prepareStatement(
                        "INSERT INTO accounts(" +
                                "   uuid, premium_uuid, password, realname, username, joined, last_seen, secret, ip, last_authentication, last_server, email" +
                                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                );
                // --- UUID ---
                ps.setString(1, user.getUuid().toString());
                ps.setString(2, user.getPremiumUUID() == null ? null : user.getPremiumUUID().toString());
                // --- Şifre formatı ---
                HashedPassword hpu = user.getHashedPassword();
                String fmt = null;
                if (hpu != null) {
                    String salt = hpu.getSalt()   == null ? "" : hpu.getSalt();
                    String hash = hpu.getHash()   == null ? "" : hpu.getHash();
                    if (salt.startsWith("$SHA$")) salt = salt.substring(5);
                    if (hash.startsWith("$SHA$")) hash = hash.substring(5);
                    if (!hash.isEmpty()) fmt = "$SHA$" + salt + "$" + hash;
                }
                ps.setString(3, fmt);
                // --- İsimler ---
                String name = user.getLastNickname();
                ps.setString(4, name);
                ps.setString(5, name);
                // --- Timestamps & diğerler ---
                ps.setTimestamp(6, user.getJoinDate());
                ps.setTimestamp(7, user.getLastSeen());
                ps.setString(8, user.getSecret());
                ps.setString(9, user.getIp());
                ps.setTimestamp(10, user.getLastAuthentication());
                ps.setString(11, user.getLastServer());
                ps.setString(12, user.getEmail());
                ps.executeUpdate();
                return null;
            });
        } catch (RuntimeException e) {
            Throwable cause = e.getCause();
            if (cause instanceof java.sql.SQLIntegrityConstraintViolationException) {
                // 1) Log’luyoruz
                plugin.getLogger().warn("Kullanıcı '" + user.getLastNickname() + "' zaten var, UUID boşsa güncellenecek.");
                // 2) Mevcut kayıtta UUID sütunu boşsa güncelleme yap
                try {
                    connector.runQuery(connection -> {
                        PreparedStatement ps2 = connection.prepareStatement(
                                "UPDATE accounts " +
                                        "SET uuid = ? " +
                                        "WHERE LOWER(realname)=LOWER(?) AND (uuid IS NULL OR uuid = '')"
                        );
                        ps2.setString(1, user.getUuid().toString());
                        ps2.setString(2, user.getLastNickname());
                        return ps2.executeUpdate();
                    });
                    plugin.getLogger().info(
                            "Eksik UUID kaydı başarıyla güncellendi: " + user.getUuid().toString()
                    );
                } catch (Exception ex) {
                    plugin.getLogger().error("Eksik UUID güncellenemedi!", ex);
                }
            } else {
                throw e;
            }
        }
    }




    @Override
    public void insertUsers(Collection<User> users) {
        plugin.reportMainThread();
        connector.runQuery(connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "INSERT " + getIgnoreSyntax() + " INTO accounts(" +
                            "uuid, premium_uuid, password, realname, username, joined, last_seen, secret, ip, last_authentication, last_server, email" +
                            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" + getIgnoreSuffix()
            );
            for (User u : users) {
                // --- Format password string: $SHA$<salt>$<hash> ---
                HashedPassword hpu = u.getHashedPassword();
                String fmt = null;
                if (hpu != null) {
                    String salt = hpu.getSalt() == null ? "" : hpu.getSalt();
                    String hash = hpu.getHash() == null ? "" : hpu.getHash();
                    // Remove any accidental prefixes from components before assembling
                    if (salt.startsWith("$SHA$")) salt = salt.substring(5);
                    if (hash.startsWith("$SHA$")) hash = hash.substring(5);
                    // Only store if hash is not empty (salt can be empty)
                    if (!hash.isEmpty()) {
                        fmt = "$SHA$" + salt + "$" + hash;
                    }
                }

                ps.setString(1, u.getUuid().toString());
                ps.setString(2, u.getPremiumUUID() == null ? null : u.getPremiumUUID().toString());
                ps.setString(3, fmt); // Set null if hpu is null or hash is empty
                String name = u.getLastNickname();
                ps.setString(4, name);
                ps.setString(5, name);
                ps.setTimestamp(6, u.getJoinDate());
                ps.setTimestamp(7, u.getLastSeen());
                ps.setString(8, u.getSecret());
                ps.setString(9, u.getIp());
                ps.setTimestamp(10, u.getLastAuthentication());
                ps.setString(11, u.getLastServer());
                ps.setString(12, u.getEmail());
                ps.addBatch();
            }
            ps.executeBatch();
        });
    }

    @Override
    public void updateUser(User user) {
        plugin.reportMainThread();
        connector.runQuery(connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "UPDATE accounts SET premium_uuid=?, password=?, realname=?, username=?, joined=?, last_seen=?, secret=?, ip=?, last_authentication=?, last_server=?, email=? WHERE uuid=?"
            );
            ps.setString(1, user.getPremiumUUID() == null ? null : user.getPremiumUUID().toString());
            // --- Format password string: $SHA$<salt>$<hash> ---
            HashedPassword hpu = user.getHashedPassword();
            String fmt = null;
            if (hpu != null) {
                String salt = hpu.getSalt() == null ? "" : hpu.getSalt();
                String hash = hpu.getHash() == null ? "" : hpu.getHash();
                // Remove any accidental prefixes from components before assembling
                if (salt.startsWith("$SHA$")) salt = salt.substring(5);
                if (hash.startsWith("$SHA$")) hash = hash.substring(5);
                 // Only store if hash is not empty (salt can be empty)
                if (!hash.isEmpty()) {
                    fmt = "$SHA$" + salt + "$" + hash;
                }
            }
            ps.setString(2, fmt); // Set null if hpu is null or hash is empty
            String name = user.getLastNickname();
            ps.setString(3, name);
            ps.setString(4, name);
            ps.setTimestamp(5, user.getJoinDate());
            ps.setTimestamp(6, user.getLastSeen());
            ps.setString(7, user.getSecret());
            ps.setString(8, user.getIp());
            ps.setTimestamp(9, user.getLastAuthentication());
            ps.setString(10, user.getLastServer());
            ps.setString(11, user.getEmail());
            ps.setString(12, user.getUuid().toString());
            ps.executeUpdate();
        });
    }

    @Override
    public void deleteUser(User user) {
        plugin.reportMainThread();
        connector.runQuery(connection -> {
            PreparedStatement ps = connection.prepareStatement("DELETE FROM accounts WHERE uuid=?");
            ps.setString(1, user.getUuid().toString());
            ps.executeUpdate();
        });
    }

    @Override
    public void validateSchema() {
        connector.runQuery(connection -> {
            Connection conn = connection;
            conn.prepareStatement(
                    "CREATE TABLE IF NOT EXISTS accounts(" +
                            "uuid VARCHAR(36) NOT NULL PRIMARY KEY," +
                            "premium_uuid VARCHAR(36) UNIQUE," +
                            "password TEXT," +
                            "realname VARCHAR(255) NOT NULL UNIQUE," +
                            "username VARCHAR(255) NOT NULL UNIQUE," +
                            "joined TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP," +
                            "last_seen TIMESTAMP NULL DEFAULT NULL," +
                            "secret VARCHAR(255) NULL DEFAULT NULL," +
                            "ip VARCHAR(45) NULL DEFAULT NULL," +
                            "last_authentication TIMESTAMP NULL DEFAULT NULL," +
                            "last_server VARCHAR(255) NULL DEFAULT NULL," +
                            "email VARCHAR(255) NULL DEFAULT NULL" +
                            ")"
            ).executeUpdate();
            List<String> cols = getColumnNames(conn);
            if (!cols.contains("username")) {
                conn.prepareStatement("ALTER TABLE accounts ADD COLUMN username VARCHAR(255) NOT NULL DEFAULT ''").executeUpdate();
            }

        });
    }

    protected abstract List<String> getColumnNames(Connection conn) throws SQLException;
    protected abstract String addUnique(String column);
    protected String getIgnoreSyntax() { return ""; }
    protected String getIgnoreSuffix() { return ""; }
}
