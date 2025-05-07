package xyz.kyngs.librelogin.common.command.commands.authorization;

import co.aikar.commands.annotation.CommandAlias;
import co.aikar.commands.annotation.CommandCompletion;
import co.aikar.commands.annotation.Default;
import co.aikar.commands.annotation.Optional;
import co.aikar.commands.annotation.Single;
import co.aikar.commands.annotation.Syntax;
import java.util.concurrent.CompletionStage;
import net.kyori.adventure.audience.Audience;
import xyz.kyngs.librelogin.api.crypto.CryptoProvider;
import xyz.kyngs.librelogin.api.crypto.HashedPassword;
import xyz.kyngs.librelogin.api.database.User;
import xyz.kyngs.librelogin.api.event.events.AuthenticatedEvent;
import xyz.kyngs.librelogin.api.event.events.WrongPasswordEvent;
import xyz.kyngs.librelogin.api.totp.TOTPProvider;
import xyz.kyngs.librelogin.common.AuthenticLibreLogin;
import xyz.kyngs.librelogin.common.command.InvalidCommandArgument;
import xyz.kyngs.librelogin.common.event.events.AuthenticWrongPasswordEvent;

@CommandAlias("login|l|log")
public class LoginCommand<P> extends AuthorizationCommand<P> {
    public LoginCommand(AuthenticLibreLogin<P, ?> premium) {
        super(premium);
    }

    @Default
    @Syntax("{@@syntax.login}")
    @CommandCompletion("%autocomplete.login")
    public CompletionStage<Void> onLogin(Audience sender, P player, @Single String password, @Optional String code) {
        return this.runAsync(() -> {
            this.checkUnauthorized(player);
            User user = this.getUser(player);
            if (!user.isRegistered()) {
                throw new InvalidCommandArgument(this.getMessage("error-not-registered", new String[0]));
            } else {
                sender.sendMessage(this.getMessage("info-logging-in", new String[0]));
                HashedPassword hashed = user.getHashedPassword();
                CryptoProvider crypto = this.getCrypto(hashed);
                if (crypto == null) {
                    throw new InvalidCommandArgument(this.getMessage("error-password-corrupted", new String[0]));
                } else if (!crypto.matches(password, hashed)) {
                    this.plugin.getEventProvider().unsafeFire(this.plugin.getEventTypes().wrongPassword, new AuthenticWrongPasswordEvent(user, player, this.plugin, WrongPasswordEvent.AuthenticationSource.LOGIN));
                    throw new InvalidCommandArgument(this.getMessage("error-password-wrong", new String[0]));
                } else {
                    String secret = user.getSecret();
                    if (secret != null) {
                        TOTPProvider totp = this.plugin.getTOTPProvider();
                        if (totp != null) {
                            if (code == null) {
                                throw new InvalidCommandArgument(this.getMessage("totp-not-provided", new String[0]));
                            }

                            int parsedCode;
                            try {
                                parsedCode = Integer.parseInt(code.trim().replace(" ", ""));
                            } catch (NumberFormatException var12) {
                                throw new InvalidCommandArgument(this.getMessage("totp-wrong", new String[0]));
                            }

                            if (!totp.verify(parsedCode, secret)) {
                                this.plugin.getEventProvider().unsafeFire(this.plugin.getEventTypes().wrongPassword, new AuthenticWrongPasswordEvent(user, player, this.plugin, WrongPasswordEvent.AuthenticationSource.TOTP));
                                throw new InvalidCommandArgument(this.getMessage("totp-wrong", new String[0]));
                            }
                        }
                    }

                    sender.sendMessage(this.getMessage("info-logged-in", new String[0]));
                    this.getAuthorizationProvider().authorize(user, player, AuthenticatedEvent.AuthenticationReason.LOGIN);
                }
            }
        });
    }
}
