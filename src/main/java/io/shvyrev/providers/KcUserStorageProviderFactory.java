package io.shvyrev.providers;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.RealmModel;

import java.util.Arrays;
import java.util.List;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.DriverManager;
import java.util.Properties;

public class KcUserStorageProviderFactory implements UserStorageProviderFactory<KcUserStorageProvider> {

    public static final String PROVIDER_ID = "polarity-user-provider";
    private static final Logger log = Logger.getLogger( KcUserStorageProviderFactory.class );

    protected static final List<ProviderConfigProperty> configMetadata;
    protected Connection conn;

    static {
        configMetadata = ProviderConfigurationBuilder.create()
                .property().name("dbHost")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Database Host")
                  .defaultValue(System.getenv("POLARITY_DB_HOST"))
                  .helpText("Database Host")
                .add().property().name("dbPort")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Database Port")
                  .defaultValue(System.getenv("POLARITY_DB_PORT"))
                  .helpText("Database Port")
                .add().property().name("dbName")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Database Name")
                  .defaultValue(System.getenv("POLARITY_DB_DATABASE"))
                  .helpText("Database Name")
                .add().property().name("dbUser")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Database User")
                  .defaultValue(System.getenv("POLARITY_DB_USER"))
                  .helpText("Database User")
                .add().property().name("dbPassword")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Database Password")
                  .defaultValue(System.getenv("POLARITY_DB_PASSWORD"))
                  .helpText("Database Password")
                .add().property().name("table")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Table")
                  .defaultValue("polarity.users")
                  .helpText("Table name")
                .add().property().name("username")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Username")
                  .defaultValue("username")
                  .helpText("Username column")
                .add().property().name("password")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Password")
                  .defaultValue("password")
                  .helpText("Password column")
                .add().property().name("hashAlgorithm")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Hash Algorithm")
                  .defaultValue("bcrypt")
                  .helpText("Hash Algorithm")
                .add().property().name("Salt")
                  .type(ProviderConfigProperty.STRING_TYPE)
                  .label("Salt")
                  .defaultValue("salt")
                  .helpText("Salt")
                .add().build();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configMetadata;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
                   throws ComponentValidationException {
        // String fp = config.getConfig().getFirst("path");
        // if (fp == null) throw new ComponentValidationException("user property file does not exist");
        // fp = EnvUtil.replace(fp);
        // File file = new File(fp);
        // if (!file.exists()) {
        //     throw new ComponentValidationException("user property file does not exist");
        // }
    }

    @Override
    public KcUserStorageProvider create(KeycloakSession session, ComponentModel model) {
      String host, port, dbName, dbUser, dbPassword, uri;
      host = model.getConfig().getFirst("dbHost");
      port = model.getConfig().getFirst("dbPort");
      dbName = model.getConfig().getFirst("dbName");
      dbUser = model.getConfig().getFirst("dbUser");
      dbPassword = model.getConfig().getFirst("dbPassword");
      uri = "jdbc:postgresql://" + host + ":" + port + "/" + dbName;

      if (host == null || port == null || dbName == null || dbUser == null || dbPassword == null) {
        log.error("$ "+ "create() called with: session = [" + session + "], model = [" + model + "]");
        log.error("Database connection parameters are not set");
        throw new ComponentValidationException("Database connection parameters are not set");
      }

      Properties props = new Properties();
      props.setProperty("user", dbUser);
      props.setProperty("password", dbPassword);
      props.setProperty("ssl", "false");

      conn = null;
      try {
        conn = DriverManager.getConnection(uri, props);
        conn.isValid(1000);
      } catch (SQLException e) {
        log.error("$ "+ "create() called with: session = [" + session + "], model = [" + model + "]");
        log.error("SqlException: " + e.getMessage());
        throw new ComponentValidationException("Database connection failed: " + e.getMessage());
      }
        return new KcUserStorageProvider(session, model, conn);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Keycloak postgres provider";
    }

    @Override
    public void close() {
        log.info("$ "+ "close() called");

        try{ conn.close(); } catch (SQLException e) {
          log.error("$ "+ "close() called");
          log.error("SqlException: " + e.getMessage());
        }
    }
}
