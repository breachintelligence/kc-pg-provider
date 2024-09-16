package io.shvyrev.providers;

import io.shvyrev.model.UserAdapter;
import io.shvyrev.model.KcUserEntity;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.*;
import java.util.stream.Stream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import at.favre.lib.crypto.bcrypt.BCrypt;

public class KcUserStorageProvider implements UserStorageProvider,
        UserLookupProvider,
        UserRegistrationProvider,
        UserQueryProvider,
        CredentialInputUpdater,
        CredentialInputValidator,
        OnUserCache {
    public static final String PASSWORD_CACHE_KEY = UserAdapter.class.getName() + ".password";
    private final KeycloakSession session;
    private final ComponentModel model;
    private final Connection conn;

    private static final Logger log = Logger.getLogger( KcUserStorageProvider.class );

    public KcUserStorageProvider(KeycloakSession session, ComponentModel model, Connection conn) {
        this.session = session;
        this.model = model;
        this.conn = conn;
    }

    @Override
    public void preRemove(RealmModel realm) {
        log.info("$ "+ "preRemove() called with: realm = [" + realm + "]");
//        INFO still not implemented
    }

    @Override
    public void preRemove(RealmModel realm, GroupModel group) {
        log.info("$ "+ "preRemove() called with: realm = [" + realm + "], group = [" + group + "]");
//        INFO still not implemented
    }

    @Override
    public void preRemove(RealmModel realm, RoleModel role) {
        log.info("$ "+ "preRemove() called with: realm = [" + realm + "], role = [" + role + "]");
//        INFO still not implemented
    }

    @Override
    public void close() {
        log.info("$ "+ "close() called");

        try {
            this.conn.close();
        } catch (SQLException e) {
            log.error("$ "+ "close() called");
        }
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        log.info("$ "+ "getUserById() called with: realm = [" + realm + "], id = [" + id + "]");

        StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();

        return getUserByUsername(realm, username);
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        log.info("$ "+ "getUserByUsername() called with: realm = [" + realm + "], username = [" + username + "]");

        String table = this.model.getConfig().getFirst("table");
        String query = "SELECT * FROM " + table + " WHERE username = ?";

        try {
            PreparedStatement stmt = this.conn.prepareStatement(query);
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                KcUserEntity entity = new KcUserEntity();
                entity.setId(rs.getString("id"));
                entity.setUsername(rs.getString("username"));
                entity.setPassword(rs.getString("password_hash"));
                entity.setEmail(rs.getString("email"));
                entity.setFirstName(rs.getString("full_name"));
                entity.setEnabled(rs.getBoolean("enabled"));

                log.info("$ "+ "getUserByUsername() called with: realm = [" + realm + "], username = [" + username + "], entity = [" + entity + "]");
                return new UserAdapter(this.session, realm, this.model, entity);
            }
        } catch (SQLException e) {
            log.error("$ "+ "getUserByUsername() called with: realm = [" + realm + "], username = [" + username + "]");
            log.error("SqlException: " + e.getMessage());
        }

        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        log.info("$ "+ "getUserByEmail() called with: realm = [" + realm + "], email = [" + email + "]");
        
        String table = this.model.getConfig().getFirst("table");
        String query = "SELECT * FROM " + table + " WHERE email = ?";

        try {
            PreparedStatement stmt = this.conn.prepareStatement(query);
            stmt.setString(1, email);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                KcUserEntity entity = new KcUserEntity();
                entity.setId(rs.getString("id"));
                entity.setUsername(rs.getString("username"));
                entity.setPassword(rs.getString("password_hash"));
                entity.setEmail(rs.getString("email"));
                entity.setFirstName(rs.getString("full_name"));
                entity.setEnabled(rs.getBoolean("enabled"));
                return new UserAdapter(this.session, realm, this.model, entity);
            }
        } catch (SQLException e) {
            log.error("$ "+ "getUserByEmail() called with: realm = [" + realm + "], email = [" + email + "]");
            log.error("SqlException: " + e.getMessage());
        }

        return null;
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        log.info("$ "+ "addUser() called with: realm = [" + realm + "], username = [" + username + "]");
        return null;
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        log.info("$ "+ "removeUser() called with: realm = [" + realm + "], user = [" + user + "]");
        return true;
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        log.info("$ "+ "onCache() called with: realm = [" + realm + "], user = [" + user + "], delegate = [" + delegate + "]");

        String password = ((UserAdapter)delegate).getPassword();
        if (password != null) {
            user.getCachedWith().put(PASSWORD_CACHE_KEY, password);
        }
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        log.info("$ "+ "supportsCredentialType() called with: credentialType = [" + credentialType + "]");

        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        log.info("$ "+ "updateCredential() called with: realm = [" + realm + "], user = [" + user + "], input = [" + input + "]");

        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) return false;
        UserCredentialModel cred = (UserCredentialModel)input;
        UserAdapter adapter = getUserAdapter(user);
        adapter.setPassword(cred.getValue());

        return true;
    }

    public UserAdapter getUserAdapter(UserModel user) {
        log.info("$ "+ "getUserAdapter() called with: user = [" + user + "]");

        if (user instanceof CachedUserModel) {
            return (UserAdapter)((CachedUserModel) user).getDelegateForUpdate();
        } else {
            return (UserAdapter) user;
        }
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        log.info("$ "+ "disableCredentialType() called with: realm = [" + realm + "], user = [" + user + "], credentialType = [" + credentialType + "]");

        if (!supportsCredentialType(credentialType)) return;

        getUserAdapter(user).setPassword(null);
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        log.info("$ "+ "getDisableableCredentialTypesStream() called with: realm = [" + realm + "], user = [" + user + "]");

        if (getUserAdapter(user).getPassword() != null) {
            Set<String> set = new HashSet<>();
            set.add(PasswordCredentialModel.TYPE);
            return set.stream();
        } else {
            return Stream.empty();
        }
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log.info("$ "+ "isConfiguredFor() called with: realm = [" + realm + "], user = [" + user + "], credentialType = [" + credentialType + "]");

        return supportsCredentialType(credentialType) && getPassword(user) != null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        log.info("$ "+ "isValid() called with: realm = [" + realm + "], user = [" + user + "], input = [" + input + "]");

        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) return false;
        UserCredentialModel cred = (UserCredentialModel)input;
        String password = getPassword(user);

        if (password == null)
          return false;

        String hex = null;
        switch (this.model.getConfig().getFirst("hashAlgorithm").toLowerCase()) {
          case "sha1":
              hex = DigestUtils.sha1Hex(input.getChallengeResponse());
              break;
          case "md5":
              hex = DigestUtils.md5Hex(input.getChallengeResponse());
              break;
          case "bcrypt":
              char[] incomingPassword = input.getChallengeResponse().toCharArray();
              return BCrypt.verifyer(BCrypt.Version.VERSION_2B).verify(incomingPassword, password.toCharArray()).verified;
        }

        return password.equalsIgnoreCase(hex);
    }

    public String getPassword(UserModel user) {
        log.info("$ "+ "getPassword() called with: user = [" + user + "]");

        String password = null;
        if (user instanceof CachedUserModel) {
            password = (String)((CachedUserModel)user).getCachedWith().get(PASSWORD_CACHE_KEY);
        } else if (user instanceof UserAdapter) {
            password = ((UserAdapter)user).getPassword();
        }
        return password;
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        log.info("$ "+ "getUsersCount() called with: realm = [" + realm + "]");

        int count = 0;
        String table = this.model.getConfig().getFirst("table");
        String query = "SELECT COUNT(*) FROM " + table;

        try {
            PreparedStatement stmt = this.conn.prepareStatement(query);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                count = rs.getInt(1);
            }
        } catch (SQLException e) {
            log.error("$ "+ "getUsersCount() called with: realm = [" + realm + "]");
            log.error("SqlException: " + e.getMessage());
        }

        return count;
    }

    public Stream<UserModel> getUsersStream(RealmModel realm, Integer firstResult, Integer maxResults) {
        log.info("$ "+ "getUsersStream() called with: realm = [" + realm + "], firstResult = [" + firstResult + "], maxResults = [" + maxResults + "]");

        String table = this.model.getConfig().getFirst("table");
        String query = "SELECT * FROM " + table + " LIMIT " + maxResults + " OFFSET " + firstResult;

        try {
            PreparedStatement stmt = this.conn.prepareStatement(query);
            ResultSet rs = stmt.executeQuery();
            List<UserModel> users = new ArrayList<>();
            while (rs.next()) {
                KcUserEntity entity = new KcUserEntity();
                entity.setId(rs.getString("id"));
                entity.setUsername(rs.getString("username"));
                entity.setPassword(rs.getString("password_hash"));
                entity.setEmail(rs.getString("email"));
                entity.setFirstName(rs.getString("full_name"));
                entity.setEnabled(rs.getBoolean("enabled"));

                log.info("entity: " + entity);

                users.add(new UserAdapter(this.session, realm, this.model, entity));
            }
            return users.stream();
        } catch (SQLException e) {
            log.error("$ "+ "getUsersStream() called with: realm = [" + realm + "], firstResult = [" + firstResult + "], maxResults = [" + maxResults + "]");
            log.error("SqlException: " + e.getMessage());
            return Stream.empty();
        }
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
        log.info("$ "+ "searchForUserStream() called with: realm = [" + realm + "], search = [" + search + "], firstResult = [" + firstResult + "], maxResults = [" + maxResults + "]");

        log.info(search);
        if (search == null || search.isEmpty()) {
            log.info(" search was empty ");
            return getUsersStream(realm, firstResult, maxResults);
        }

        if (search == "*") {
            log.info(" search was wild card ");
            return getUsersStream(realm, firstResult, maxResults);
        }

        String table = this.model.getConfig().getFirst("table");
        String searchPattern = "%" + search + "%";
        String query = "SELECT * FROM " + table + " WHERE username LIKE ? LIMIT " + maxResults + " OFFSET " + firstResult;

        try {
            PreparedStatement stmt = this.conn.prepareStatement(query);
            stmt.setString(1, searchPattern);
            ResultSet rs = stmt.executeQuery();
            List<UserModel> users = new ArrayList<>();
            while (rs.next()) {
                KcUserEntity entity = new KcUserEntity();
                entity.setId(rs.getString("id"));
                entity.setUsername(rs.getString("username"));
                entity.setPassword(rs.getString("password_hash"));
                entity.setEmail(rs.getString("email"));
                entity.setFirstName(rs.getString("full_name"));
                entity.setEnabled(rs.getBoolean("enabled"));

                log.info("entity: " + entity);

                users.add(new UserAdapter(this.session, realm, this.model, entity));
            }
            return users.stream();
        } catch (SQLException e) {
            log.error("$ "+ "searchForUserStream() called with: realm = [" + realm + "], search = [" + search + "], firstResult = [" + firstResult + "], maxResults = [" + maxResults + "]");
            log.error("SqlException: " + e.getMessage());
            return Stream.empty();
        }
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        log.info("$ "+ "searchForUserStream() called with: realm = [" + realm + "], params = [" + params + "], firstResult = [" + firstResult + "], maxResults = [" + maxResults + "]");
        
        String search = params.get("keycloak.session.realm.users.query.search");
        return searchForUserStream(realm, search, firstResult, maxResults);
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        log.info("$ "+ "getGroupMembersStream() called with: realm = [" + realm + "], group = [" + group + "], firstResult = [" + firstResult + "], maxResults = [" + maxResults + "]");
//        INFO still not implemented
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        log.info("$ "+ "searchForUserByUserAttributeStream() called with: realm = [" + realm + "], attrName = [" + attrName + "], attrValue = [" + attrValue + "]");
//        INFO still not implemented
        return Stream.empty();
    }
}
