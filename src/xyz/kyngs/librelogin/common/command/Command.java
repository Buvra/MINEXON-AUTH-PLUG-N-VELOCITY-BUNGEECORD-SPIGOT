package xyz.kyngs.librelogin.common.command;

import co.aikar.commands.BaseCommand;
import co.aikar.commands.MessageKeys;
import co.aikar.locales.MessageKeyProvider;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import net.kyori.adventure.audience.Audience;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.TextComponent;
import xyz.kyngs.librelogin.api.Logger;
import xyz.kyngs.librelogin.api.configuration.Messages;
import xyz.kyngs.librelogin.api.crypto.CryptoProvider;
import xyz.kyngs.librelogin.api.crypto.HashedPassword;
import xyz.kyngs.librelogin.api.database.ReadWriteDatabaseProvider;
import xyz.kyngs.librelogin.api.database.User;
import xyz.kyngs.librelogin.common.AuthenticLibreLogin;
import xyz.kyngs.librelogin.common.authorization.AuthenticAuthorizationProvider;
import xyz.kyngs.librelogin.common.util.GeneralUtil;

public class Command<P>
        extends BaseCommand {
    protected final AuthenticLibreLogin<P, ?> plugin;

    public Command(AuthenticLibreLogin<P, ?> plugin) {
        this.plugin = plugin;
    }

    protected ReadWriteDatabaseProvider getDatabaseProvider() {
        return this.plugin.getDatabaseProvider();
    }

    protected Logger getLogger() {
        return this.plugin.getLogger();
    }

    protected Messages getMessages() {
        return this.plugin.getMessages();
    }

    protected TextComponent getMessage(String key, String ... replacements) {
        return this.getMessages().getMessage(key, replacements);
    }

    protected AuthenticAuthorizationProvider<P, ?> getAuthorizationProvider() {
        return this.plugin.getAuthorizationProvider();
    }

    protected void checkAuthorized(P player) {
        if (!this.getAuthorizationProvider().isAuthorized(player)) {
            throw new InvalidCommandArgument(this.getMessage("error-not-authorized", new String[0]));
        }
    }

protected CryptoProvider getCrypto(HashedPassword password) {
    // Assuming the algorithm is fixed to "SHA-256"
    return this.plugin.getCryptoProvider("SHA-256");
}

    public CompletionStage<Void> runAsync(Runnable runnable) {
        return GeneralUtil.runAsync(runnable);
    }

    protected User getUser(P player) {
        if (player == null) {
            throw new co.aikar.commands.InvalidCommandArgument((MessageKeyProvider)MessageKeys.NOT_ALLOWED_ON_CONSOLE, false, new String[0]);
        }
        UUID uuid = this.plugin.getPlatformHandle().getUUIDForPlayer(player);
        if (this.plugin.fromFloodgate(uuid)) {
            throw new InvalidCommandArgument(this.getMessage("error-from-floodgate", new String[0]));
        }
        return this.plugin.getDatabaseProvider().getByUUID(uuid);
    }

    protected void setPassword(Audience sender, User user, String password, String messageKey) {
        if (!this.plugin.validPassword(password)) {
            throw new InvalidCommandArgument(this.getMessage("error-forbidden-password", new String[0]));
        }
        sender.sendMessage((Component)this.getMessage(messageKey, new String[0]));
        CryptoProvider defaultProvider = this.plugin.getDefaultCryptoProvider();
        HashedPassword hash = defaultProvider.createHash(password);
        if (hash == null) {
            throw new InvalidCommandArgument(this.getMessage("error-password-too-long", new String[0]));
        }
        user.setHashedPassword(hash);
    }
}
