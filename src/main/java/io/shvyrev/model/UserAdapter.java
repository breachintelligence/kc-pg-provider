package io.shvyrev.model;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

public class UserAdapter extends AbstractUserAdapterFederatedStorage {

    private static final Logger log = Logger.getLogger( UserAdapter.class );
    private final KcUserEntity entity;

    //        INFO still not implemented
    private final String keycloakId;

    public UserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, KcUserEntity entity) {
        super(session, realm, model);

        this.entity = entity;
        keycloakId = StorageId.keycloakId(model, entity.getId().toString());
    }

    public String getPassword() {
        log.info("$ "+ "getPassword() called " + entity.getPassword());
        return entity.getPassword();
    }

    public void setPassword(String password) {
        log.info("$ "+ "setPassword() called with: password = [" + password + "]");

        entity.setPassword(password);
    }

    @Override
    public String getUsername() {
        log.info("$ "+ "getUsername() called " + entity.getUsername());
        return entity.getUsername();
    }

    @Override
    public void setUsername(String username) {
        log.info("$ "+ "setUsername() called with: username = [" + username + "]");

        entity.setUsername(username);
    }

    @Override
    public String getEmail() {
        log.info("$ "+ "getEmail() called " + entity.getEmail());
        return entity.getEmail();
    }

    @Override
    public void setEmail(String email) {
        log.info("$ "+ "setEmail() called with: email = [" + email + "]");

        entity.setEmail(email);
    }

    @Override
    public String getFirstName() {
        log.info("$ "+ "getFirstName() called " + entity.getFirstName());
        return entity.getFirstName();
    }

    @Override
    public void setFirstName(String firstName) {
        log.info("$ "+ "setFirstName() called with: firstName = [" + firstName + "]");

        entity.setFirstName(firstName);
    }

    @Override
    public String getLastName() {
        log.info("getLastName() called " + entity.getLastName());
        return entity.getLastName();
    }

    @Override
    public void setLastName(String lastName) {
        log.info("$ "+ "setLastName() called with: lastName = [" + lastName + "]");

        entity.setLastName(lastName);
    }

    @Override
    public boolean isEmailVerified() {
        log.info("$ "+ "isEmailVerified() called");
        return true;
    }

    @Override
    public boolean isEnabled() {
        log.info("$ "+ "isEnabled() called");
        return entity.isEnabled();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        log.info("$ "+ "getAttributes() called");
        
        HashMap<String, List<String>> attributes = new HashMap<String, List<String>>();
        attributes.put("username", Collections.singletonList(entity.getUsername()));
        attributes.put("firstName", Collections.singletonList(entity.getFirstName()));
        attributes.put("lastName", Collections.singletonList(entity.getLastName()));
        attributes.put("email", Collections.singletonList(entity.getEmail()));

        return attributes;
    }

    @Override
    public String toString() {
        return "UserAdapter{" +
                "entity=" + entity +
                ", keycloakId='" + keycloakId + '\'' +
                '}';
    }


}
