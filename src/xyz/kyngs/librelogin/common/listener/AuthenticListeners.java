package xyz.kyngs.librelogin.common.listener;

import java.net.InetAddress;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.regex.Pattern;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.TextComponent;
import xyz.kyngs.librelogin.api.BiHolder;
import xyz.kyngs.librelogin.api.PlatformHandle;
import xyz.kyngs.librelogin.api.crypto.HashedPassword;
import xyz.kyngs.librelogin.api.database.User;
import xyz.kyngs.librelogin.api.event.events.AuthenticatedEvent;
import xyz.kyngs.librelogin.api.premium.PremiumException;
import xyz.kyngs.librelogin.api.premium.PremiumUser;
import xyz.kyngs.librelogin.common.AuthenticLibreLogin;
import xyz.kyngs.librelogin.common.authorization.AuthenticAuthorizationProvider;
import xyz.kyngs.librelogin.common.authorization.ProfileConflictResolutionStrategy;
import xyz.kyngs.librelogin.common.command.InvalidCommandArgument;
import xyz.kyngs.librelogin.common.config.ConfigurationKeys;
import xyz.kyngs.librelogin.common.database.AuthenticUser;
import xyz.kyngs.librelogin.common.event.AuthenticEventProvider;
import xyz.kyngs.librelogin.common.event.events.AuthenticAuthenticatedEvent;
import org.jetbrains.annotations.Nullable;

public class AuthenticListeners<Plugin extends AuthenticLibreLogin<P, S>, P, S> {
    private static final Pattern NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_]*");
    protected final Plugin plugin;
    protected final PlatformHandle<P, S> platformHandle;

    public AuthenticListeners(Plugin plugin) {
        this.plugin = plugin;
        this.platformHandle = plugin.getPlatformHandle();
    }

protected void onPostLogin(P player, User initiallyPassedUser) { // Renamed param for clarity
    String ip = this.platformHandle.getIP(player);
    UUID correctUuid = this.platformHandle.getUUIDForPlayer(player); // Correct UUID from platform

    if (((AuthenticLibreLogin)this.plugin).fromFloodgate(correctUuid)) {
        return; // Skip Floodgate users
    }

    User userByCorrectUuid = ((AuthenticLibreLogin)this.plugin).getDatabaseProvider().getByUUID(correctUuid);
    User finalUserToProcess = null;
    String usernameForLogging = "UNKNOWN"; // Default username for logging if user cannot be loaded

    if (userByCorrectUuid != null) {
        // Found user by the correct UUID, this is the ideal case.
        finalUserToProcess = userByCorrectUuid;
        usernameForLogging = finalUserToProcess.getLastNickname(); // Get username from loaded user
        // Optional: Check if initiallyPassedUser (from pre-login, maybe loaded by name) exists and differs
        if (initiallyPassedUser != null && !initiallyPassedUser.getUuid().equals(correctUuid)) {
            plugin.getLogger().warn("User " + usernameForLogging + " (UUID: " + correctUuid + ") loaded correctly by UUID, but pre-login might have passed a user object with a different UUID (" + initiallyPassedUser.getUuid() + "). This could indicate a duplicate record needing cleanup.");
        }
    } else {
        // Not found by correct UUID. Check the user passed from pre-login.
        if (initiallyPassedUser != null) {
            usernameForLogging = initiallyPassedUser.getLastNickname(); // Get username from initially passed user
            UUID storedUuid = initiallyPassedUser.getUuid(); // The (potentially incorrect) UUID found during pre-login

            if (!storedUuid.equals(correctUuid)) {
                 // Found by name during pre-login (implied), but stored UUID is wrong.
                 plugin.getLogger().error("CRITICAL: User " + usernameForLogging + " (Platform UUID: " + correctUuid + ") could not be found by the correct UUID. A record was found with the same name but an incorrect stored UUID (" + storedUuid + "). The stored UUID needs to be corrected in the database manually. Using the record with the incorrect UUID for this session.");
                 // Use the user data found during pre-login (with the wrong UUID) for this session.
                 finalUserToProcess = initiallyPassedUser;
            } else {
                 // UUIDs match, but lookup by correctUuid failed? This indicates an unexpected inconsistency.
                 plugin.getLogger().error("Internal inconsistency: User " + usernameForLogging + " (UUID: " + correctUuid + ") not found by UUID lookup, but pre-login passed a user with the matching UUID. Aborting.");
                 return; // Abort due to inconsistent state
            }
        } else {
            // Not found by correct UUID AND no user passed from pre-login.
            // Try getting username from platform handle if possible (may not exist) for logging
            try {
                 // Attempt to get username directly - THIS MIGHT FAIL depending on PlatformHandle implementation
                 // String currentUsername = this.platformHandle.getUsername(player); // This was the incorrect assumption
                 // If there's no standard way, we might have to rely on pre-login logs or skip username here.
                 usernameForLogging = "PlayerWithUUID_" + correctUuid; // Fallback logging name
            } catch (Exception e) {
                 usernameForLogging = "PlayerWithUUID_" + correctUuid; // Fallback logging name
            }
            plugin.getLogger().error("User " + usernameForLogging + " (UUID: " + correctUuid + ") could not be found by UUID and no user data was passed from pre-login. Aborting further processing. The user might need to register.");
            // Optionally kick the player
            // platformHandle.kickPlayer(player, plugin.getMessages().getMessage("kick-user-not-found"));
            return; // Exit the method
        }
    }

    // If we reach here, finalUserToProcess should be non-null
    if (finalUserToProcess == null) {
         // This case should theoretically not be reached due to the logic above, but as a safeguard:
         plugin.getLogger().error("Internal error: finalUserToProcess is null in onPostLogin for " + usernameForLogging + ". Aborting.");
         return;
    }

    // --- Proceed with existing logic using finalUserToProcess ---
    Duration sessionTime = Duration.ofSeconds(((AuthenticLibreLogin)this.plugin).getConfiguration().get(ConfigurationKeys.SESSION_TIMEOUT));

    // Use finalUserToProcess for all subsequent checks and updates
    if (finalUserToProcess.autoLoginEnabled()) {
        ((AuthenticLibreLogin)this.plugin).delay(() -> ((AuthenticLibreLogin)this.plugin).getPlatformHandle().getAudienceForPlayer(player).sendMessage((Component)((AuthenticLibreLogin)this.plugin).getMessages().getMessage("info-premium-logged-in", new String[0])), 500L);
        ((AuthenticEventProvider)((AuthenticLibreLogin)this.plugin).getEventProvider()).fire(this.plugin.getEventTypes().authenticated, new AuthenticAuthenticatedEvent(finalUserToProcess, player, this.plugin, AuthenticatedEvent.AuthenticationReason.PREMIUM));
    } else if (sessionTime != null && finalUserToProcess.getLastAuthentication() != null && ip.equals(finalUserToProcess.getIp()) && finalUserToProcess.getLastAuthentication().toLocalDateTime().plus(sessionTime).isAfter(LocalDateTime.now())) {
        ((AuthenticLibreLogin)this.plugin).delay(() -> ((AuthenticLibreLogin)this.plugin).getPlatformHandle().getAudienceForPlayer(player).sendMessage((Component)((AuthenticLibreLogin)this.plugin).getMessages().getMessage("info-session-logged-in", new String[0])), 500L);
        ((AuthenticEventProvider)((AuthenticLibreLogin)this.plugin).getEventProvider()).fire(this.plugin.getEventTypes().authenticated, new AuthenticAuthenticatedEvent(finalUserToProcess, player, this.plugin, AuthenticatedEvent.AuthenticationReason.SESSION));
    } else {
        ((AuthenticAuthorizationProvider)((AuthenticLibreLogin)this.plugin).getAuthorizationProvider()).startTracking(finalUserToProcess, player);
    }

    // Update last seen and IP using finalUserToProcess
    finalUserToProcess.setLastSeen(Timestamp.valueOf(LocalDateTime.now()));
    finalUserToProcess.setIp(ip); // Update IP address on successful login/session continuation

    // Update the user record in the database (using its potentially incorrect UUID if loaded by name)
    User userToSave = finalUserToProcess; // Clarity
    ((AuthenticLibreLogin)this.plugin).delay(() -> ((AuthenticLibreLogin)this.plugin).getDatabaseProvider().updateUser(userToSave), 0L);
}

    protected void onPlayerDisconnect(P player) {
        this.plugin.onExit(player);
        this.plugin.getAuthorizationProvider().onExit(player);
    }

    protected PreLoginResult onPreLogin(String username, InetAddress address) {
        if (username.length() <= 16 && NAME_PATTERN.matcher(username).matches()) {
            PremiumUser mojangData;
            try {
                mojangData = this.plugin.getPremiumProvider().getUserForName(username);
            } catch (PremiumException var11) {
                TextComponent var10000;
                switch(var11.getIssue()) {
                    case THROTTLED:
                        var10000 = this.plugin.getMessages().getMessage("kick-premium-error-throttled");
                        break;
                    default:
                        this.plugin.getLogger().error("Encountered an exception while communicating with the Mojang API!");
                        var11.printStackTrace();
                        var10000 = this.plugin.getMessages().getMessage("kick-premium-error-undefined");
                }

                TextComponent message = var10000;
                return new PreLoginResult(PreLoginState.DENIED, message, (User)null);
            }

            if (mojangData == null) {
                User user;
                try {
                    user = this.checkAndValidateByName(username, (PremiumUser)null, true, address);
                } catch (InvalidCommandArgument var9) {
                    return new PreLoginResult(PreLoginState.DENIED, var9.getUserFuckUp(), (User)null);
                }

                if (user.getPremiumUUID() != null) {
                    return new PreLoginResult(PreLoginState.FORCE_ONLINE, (Component)null, user);
                }
            } else {
                UUID premiumID = mojangData.uuid();
                User user = this.plugin.getDatabaseProvider().getByPremiumUUID(premiumID);
                User userByName;
                if (user != null) {
                    try {
                        userByName = this.checkAndValidateByName(username, mojangData, false, address);
                    } catch (InvalidCommandArgument var10) {
                        return new PreLoginResult(PreLoginState.DENIED, var10.getUserFuckUp(), (User)null);
                    }

                    if (userByName != null && !user.equals(userByName)) {
                        return this.handleProfileConflict(user, userByName);
                    }

                    if (!mojangData.reliable()) {
                        this.plugin.getLogger().warn("User %s has probably changed their name. Data returned from Mojang API is not reliable, faking a new one using the current nickname.".formatted(new Object[]{username}));
                        mojangData = new PremiumUser(mojangData.uuid(), username, false);
                    }

                    if (!user.getLastNickname().contentEquals(mojangData.name())) {
                        user.setLastNickname(mojangData.name());
                        this.plugin.getDatabaseProvider().updateUser(user);
                    }

                    return new PreLoginResult(PreLoginState.FORCE_ONLINE, (Component)null, user);
                }

                try {
                    userByName = this.checkAndValidateByName(username, mojangData, true, address);
                } catch (InvalidCommandArgument var8) {
                    return new PreLoginResult(PreLoginState.DENIED, var8.getUserFuckUp(), (User)null);
                }

                if (userByName.autoLoginEnabled()) {
                    return new PreLoginResult(PreLoginState.FORCE_ONLINE, (Component)null, userByName);
                }
            }

            return new PreLoginResult(PreLoginState.FORCE_OFFLINE, (Component)null, (User)null);
        } else {
            return new PreLoginResult(PreLoginState.DENIED, this.plugin.getMessages().getMessage("kick-illegal-username"), (User)null);
        }
    }

    private PreLoginResult handleProfileConflict(User conflicting, User conflicted) {
        PreLoginResult var10000;
        switch(ProfileConflictResolutionStrategy.valueOf((String)this.plugin.getConfiguration().get(ConfigurationKeys.PROFILE_CONFLICT_RESOLUTION_STRATEGY))) {
            case BLOCK:
                var10000 = new PreLoginResult(PreLoginState.DENIED, this.plugin.getMessages().getMessage("kick-name-mismatch", "%nickname%", conflicting.getLastNickname()), (User)null);
                break;
            case USE_OFFLINE:
                var10000 = new PreLoginResult(PreLoginState.FORCE_OFFLINE, (Component)null, (User)null);
                break;
            case OVERWRITE:
                this.plugin.getDatabaseProvider().deleteUser(conflicted);
                conflicting.setLastNickname(conflicted.getLastNickname());
                this.plugin.getDatabaseProvider().updateUser(conflicting);
                var10000 = new PreLoginResult(PreLoginState.FORCE_ONLINE, (Component)null, conflicting);
                break;
            default:
                throw new MatchException((String)null, (Throwable)null);
        }

        return var10000;
    }

    private User checkAndValidateByName(String username, @Nullable PremiumUser premiumUser, boolean generate, InetAddress ip) throws InvalidCommandArgument {
        User user = this.plugin.getDatabaseProvider().getByName(username);
        if (user != null) {
            // User found by name
            if (!user.getLastNickname().contentEquals(username)) {
                // Existing user found, but username case doesn't match requested name
                throw new InvalidCommandArgument(this.plugin.getMessages().getMessage("kick-invalid-case-username", "%username%", user.getLastNickname()));
            }
            // User exists and name case matches, return the found user immediately.
            return user;
        } else {
            // User not found by name. Proceed with generation logic ONLY if generate is true.
            if (!generate) {
                return null; // Do not generate if not requested
            }

            Integer minLength = (Integer)this.plugin.getConfiguration().get(ConfigurationKeys.MINIMUM_USERNAME_LENGTH);
            if (username.length() < minLength) {
                throw new InvalidCommandArgument(this.plugin.getMessages().getMessage("kick-short-username", "%length%", String.valueOf(minLength)));
            }

            Integer ipLimit = (Integer)this.plugin.getConfiguration().get(ConfigurationKeys.IP_LIMIT);
            if (ipLimit > 0) {
                int ipCount = this.plugin.getDatabaseProvider().getByIP(ip.getHostAddress()).size();
                if (ipCount >= ipLimit) {
                    throw new InvalidCommandArgument(this.plugin.getMessages().getMessage("kick-ip-limit", "%limit%", String.valueOf(ipLimit)));
                }
            }

            UUID newID = this.plugin.generateNewUUID(username, premiumUser == null ? null : premiumUser.uuid());
            User conflictingUser = this.plugin.getDatabaseProvider().getByUUID(newID);
            if (conflictingUser != null) {
                throw new InvalidCommandArgument(this.plugin.getMessages().getMessage("kick-occupied-username", "%username%", conflictingUser.getLastNickname()));
            }

            if (premiumUser != null && premiumUser.reliable() && (Boolean)this.plugin.getConfiguration().get(ConfigurationKeys.AUTO_REGISTER)) {
                if (!premiumUser.name().contentEquals(username)) {
                    throw new InvalidCommandArgument(this.plugin.getMessages().getMessage("kick-invalid-case-username", "%username%", premiumUser.name()));
                }

                user = new AuthenticUser(newID, premiumUser.uuid(), (HashedPassword)null, username, Timestamp.valueOf(LocalDateTime.now()), Timestamp.valueOf(LocalDateTime.now()), (String)null, ip.getHostAddress(), (Timestamp)null, (String)null, (String)null);
            } else {
                if (premiumUser != null && !premiumUser.reliable()) {
                    this.plugin.getLogger().warn("The premium data for %s is not reliable, the user may not have the same name capitalization as the premium one. It is not safe to auto-register this user. Switching to offline registration!".formatted(new Object[]{username}));
                }

                user = new AuthenticUser(newID, (UUID)null, (HashedPassword)null, username, Timestamp.valueOf(LocalDateTime.now()), Timestamp.valueOf(LocalDateTime.now()), (String)null, ip.getHostAddress(), (Timestamp)null, (String)null, (String)null);
            }

            this.plugin.getDatabaseProvider().insertUser((User)user);
        }

        return (User)user;
    }

    protected BiHolder<Boolean, S> chooseServer(P player, @Nullable String ip, @Nullable User user) {
        UUID id = this.platformHandle.getUUIDForPlayer(player);
        boolean fromFloodgate = this.plugin.fromFloodgate(id);
        Duration sessionTime = Duration.ofSeconds((Long)this.plugin.getConfiguration().get(ConfigurationKeys.SESSION_TIMEOUT));
        if (fromFloodgate) {
            user = null;
        } else if (user == null) {
            user = this.plugin.getDatabaseProvider().getByUUID(id);
        }

        if (ip == null) {
            ip = this.platformHandle.getIP(player);
        }

        // Add null check for user before attempting to access its methods
        if (user == null) {
            // If user is null (not found/loaded), send to limbo
            plugin.getLogger().warn("User not found for UUID: " + id + " during server choice. Sending to limbo.");
            return new BiHolder<>(false, this.plugin.getServerHandler().chooseLimboServer(null, player)); // Pass null for user to limbo handler if needed
        }

        // User is not null, proceed with the original logic
        boolean needsAuthentication = !fromFloodgate && !user.autoLoginEnabled() &&
                (sessionTime == null || user.getLastAuthentication() == null || !ip.equals(user.getIp()) || !user.getLastAuthentication().toLocalDateTime().plus(sessionTime).isAfter(LocalDateTime.now()));

        return needsAuthentication ?
                new BiHolder<>(false, this.plugin.getServerHandler().chooseLimboServer(user, player)) :
                new BiHolder<>(true, this.plugin.getServerHandler().chooseLobbyServer(user, player, true, false));
    }
}
