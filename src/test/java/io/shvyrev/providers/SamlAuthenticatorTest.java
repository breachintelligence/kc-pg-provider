package io.shvyrev.providers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class SamlAuthenticatorTest {

    private SamlAuthenticatorFactory factory;
    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private AuthenticationFlowContext context;

    @BeforeEach
    public void setUp() {
      factory = new SamlAuthenticatorFactory();
      session = mock(KeycloakSession.class);
      realm = mock(RealmModel.class);
      user = mock(UserModel.class);
      context = mock(AuthenticationFlowContext.class);
    }

    @Test
    public void testFactoryLoaded() {
        setUp();
        assertNotNull(factory);
        assertEquals("saml-authenticator", factory.getId());
    }

    @Test
    public void testAuthenticatorCreation() {
        setUp();
        SamlAuthenticator authenticator = (SamlAuthenticator) factory.create(session);
        assertNotNull(authenticator);
    }

    @Test
    public void testFactoryConfigProperties() {
      setUp();
        List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
        assertNotNull(configProperties);
        assertFalse(configProperties.isEmpty());
        assertEquals("hostname", configProperties.get(0).getName());
    }

    @Test
    public void testAuthenticatorAuthenticate() {
      setUp();
        SamlAuthenticator authenticator = (SamlAuthenticator) factory.create(session);
        when(context.getHttpRequest().getDecodedFormParameters().getFirst("username")).thenReturn("testuser");
        when(context.getHttpRequest().getDecodedFormParameters().getFirst("password")).thenReturn("testpassword");
        when(context.getAuthenticatorConfig().getConfig().get("hostname")).thenReturn("localhost");

        authenticator.authenticate(context);

        verify(context).failure(any(), any());
    }
}