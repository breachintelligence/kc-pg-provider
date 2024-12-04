package io.shvyrev.providers;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

import java.io.IOException;

public class SamlAuthenticator implements Authenticator {    
  
    private static final Logger log = Logger.getLogger( SamlAuthenticator.class );
    static {
        log.info("SamlAuthenticator loaded");
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String hostname = context.getAuthenticatorConfig().getConfig().get("hostname");        
        String username = context.getHttpRequest().getDecodedFormParameters().getFirst("username");
        String password = context.getHttpRequest().getDecodedFormParameters().getFirst("password");  
        
        log.info("Authenticating user " + username + " with external service at " + hostname);

        if (authenticateWithExternalService(hostname, username, password)) {
            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);
            if (user != null) {
                context.setUser(user);
                context.success();
                return;
            }
        }

        context.failure(AuthenticationFlowError.INVALID_USER, context.form().setError(Messages.INVALID_USER).createForm("login.ftl"));
    }

    private boolean authenticateWithExternalService(String hostname, String username, String password) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            String usernameEscaped = username.replace("\"", "\\\"");
            String passwordEscaped = password.replace("\"", "\\\"");

            HttpPost post = new HttpPost(String.format("https://%s/api/users/auth", hostname));
            log.info("Sending POST request to " + post.getURI());

            String json = String.format("{\"username\":\"%s\", \"password\":\"%s\"}", usernameEscaped, passwordEscaped);
            post.setEntity(new StringEntity(json));
            post.setHeader("Content-type", "application/json");

            try (CloseableHttpResponse response = client.execute(post)) {
                log.info("Response status: " + response.getStatusLine().getStatusCode());
                return response.getStatusLine().getStatusCode() == 200;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {}

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}