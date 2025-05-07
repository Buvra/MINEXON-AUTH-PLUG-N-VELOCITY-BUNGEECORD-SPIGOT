package xyz.kyngs.librelogin.common.database.provider;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import xyz.kyngs.librelogin.api.database.connector.MySQLDatabaseConnector;
import xyz.kyngs.librelogin.common.AuthenticLibreLogin;
import xyz.kyngs.librelogin.common.database.connector.AuthenticMySQLDatabaseConnector;

public class LibreLoginMySQLDatabaseProvider
        extends LibreLoginSQLDatabaseProvider {
    public LibreLoginMySQLDatabaseProvider(MySQLDatabaseConnector connector, AuthenticLibreLogin<?, ?> plugin) {
        super(connector, plugin);
    }

    @Override
    protected List<String> getColumnNames(Connection connection) throws SQLException {
        ResultSet resultSet = connection.prepareStatement("SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='accounts' and TABLE_SCHEMA='" + (String)((AuthenticMySQLDatabaseConnector)((Object)this.connector)).get(AuthenticMySQLDatabaseConnector.Configuration.NAME) + "'").executeQuery();
        ArrayList<String> columns = new ArrayList<String>();
        while (resultSet.next()) {
            columns.add(resultSet.getString("column_name"));
        }
        return columns;
    }

    @Override
    protected String getIgnoreSyntax() {
        return "IGNORE";
    }

    @Override
    protected String addUnique(String column) {
        return "CREATE UNIQUE INDEX %s_index ON accounts(%s)".formatted(new Object[]{column, column});
    }
}