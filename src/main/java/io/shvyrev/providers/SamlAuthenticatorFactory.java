package io.shvyrev.providers;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.jboss.logging.Logger;


import java.util.List;

public class SamlAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "saml-authenticator";
    private static final Logger log = Logger.getLogger( SamlAuthenticatorFactory.class );
    static {
        log.info("SamlAuthenticatorFactory loaded");
    }

    protected static final List<ProviderConfigProperty> configMetadata;

    static {
        configMetadata = ProviderConfigurationBuilder.create()
          .property().name("hostname")
          .type(ProviderConfigProperty.STRING_TYPE)
          .label("Hostname")
          .helpText("Hostname of the external service")
        .add().build();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        log.info("Creating new SamlAuthenticator");
        return new SamlAuthenticator();
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "SAML Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Authenticator that checks username and password against an external service during SAML login.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configMetadata;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[]{Requirement.REQUIRED};
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isUserSetupAllowed() {
      return false;
    }
}