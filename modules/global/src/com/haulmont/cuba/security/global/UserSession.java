/*
 * Copyright (c) 2008-2016 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.haulmont.cuba.security.global;

import com.haulmont.chile.core.model.MetaClass;
import com.haulmont.cuba.core.sys.UserInvocationContext;
import com.haulmont.cuba.security.app.RoleDefinitionBuilder;
import com.haulmont.cuba.security.app.RoleDefinitionsJoiner;
import com.haulmont.cuba.security.entity.*;
import com.haulmont.cuba.security.group.BasicSetOfAccessConstraints;
import com.haulmont.cuba.security.group.SetOfAccessConstraints;
import com.haulmont.cuba.security.role.PermissionsContainer;
import com.haulmont.cuba.security.role.PermissionsUtils;
import com.haulmont.cuba.security.role.RoleDefinition;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Class that encapsulates an active user session.
 * <p>It contains user attributes, credentials, set of permissions, and methods to check permissions for certain
 * objects.</p>
 * <p>On the client side a descendant of this class is maintained:
 * {@code com.haulmont.cuba.client.ClientUserSession}</p>
 */
public class UserSession implements Serializable {

    private static final long serialVersionUID = -8248326616891177382L;

    protected UUID id;
    protected User user;
    protected User substitutedUser;
    protected List<String> roles = new ArrayList<>();
    protected Locale locale;
    protected TimeZone timeZone;
    protected String address;
    protected String clientInfo;
    protected boolean system;

    protected RoleDefinition joinedRole;
    protected Access permissionUndefinedAccessPolicy = Access.DENY;
    protected SetOfAccessConstraints setOfAccessConstraints;

    protected Map<String, Serializable> attributes;

    protected transient Map<String, Object> localAttributes;

    /**
     * INTERNAL
     * Used only for kryo serialization
     */
    public UserSession() {
        localAttributes = new ConcurrentHashMap<>();
    }

    /**
     * INTERNAL
     */
    public UserSession(UUID id, User user, Collection<RoleDefinition> roles, Locale locale, boolean system) {
        this.id = id;
        this.user = user;
        this.system = system;

        for (RoleDefinition role : roles) {
            this.roles.add(role.getName());
        }

        this.locale = locale;
        if (user.getTimeZone() != null)
            this.timeZone = TimeZone.getTimeZone(user.getTimeZone());

        joinedRole = RoleDefinitionBuilder.create().build();

        setOfAccessConstraints = new BasicSetOfAccessConstraints();

        attributes = new ConcurrentHashMap<>();
        localAttributes = new ConcurrentHashMap<>();
    }

    /**
     * INTERNAL
     */
    public UserSession(UserSession src, User user, Collection<RoleDefinition> roles, Locale locale) {
        this(src.id, user, roles, locale, src.system);
        this.user = src.user;
        this.substitutedUser = this.user.equals(user) ? null : user;
    }

    /**
     * INTERNAL
     */
    public UserSession(UserSession src) {
        id = src.id;
        user = src.user;
        substitutedUser = src.substitutedUser;
        system = src.system;
        roles = src.roles;
        locale = src.locale;
        timeZone = src.timeZone;
        joinedRole = src.joinedRole;
        setOfAccessConstraints = src.setOfAccessConstraints;
        attributes = src.attributes;
        localAttributes = src.localAttributes;
        address = src.address;
        clientInfo = src.clientInfo;
        permissionUndefinedAccessPolicy = src.permissionUndefinedAccessPolicy;
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();
        localAttributes = new ConcurrentHashMap<>();
    }

    /**
     * Session ID
     */
    public UUID getId() {
        return id;
    }

    /**
     * Logged-in user
     */
    public User getUser() {
        return user;
    }

    /**
     * INTERNAL
     */
    public void setUser(User user) {
        this.user = user;
    }

    /**
     * Substituted user. May be null.
     */
    public User getSubstitutedUser() {
        return substitutedUser;
    }

    /**
     * INTERNAL
     */
    public void setSubstitutedUser(User substitutedUser) {
        this.substitutedUser = substitutedUser;
    }

    /**
     * Returns substituted user if it is not null, logged-in user otherwise.
     */
    public User getCurrentOrSubstitutedUser() {
        return substitutedUser == null ? user : substitutedUser;
    }

    /**
     * User role names
     */
    public Collection<String> getRoles() {
        return Collections.unmodifiableList(roles);
    }

    /**
     * User locale
     */
    public Locale getLocale() {
        Locale requestScopeLocale = UserInvocationContext.getRequestScopeLocale(id);
        if (requestScopeLocale != null) {
            return requestScopeLocale;
        }

        return locale;
    }

    /**
     * INTERNAL
     */
    public void setLocale(Locale locale) {
        this.locale = locale;
    }

    /**
     * User time zone. Can be null.
     */
    @Nullable
    public TimeZone getTimeZone() {
        TimeZone requestScopeTimeZone = UserInvocationContext.getRequestScopeTimeZone(id);
        if (requestScopeTimeZone != null) {
            return requestScopeTimeZone;
        }

        return timeZone;
    }

    /**
     * INTERNAL
     */
    public void setTimeZone(TimeZone timeZone) {
        this.timeZone = timeZone;
    }

    /**
     * Client IP-address
     */
    public String getAddress() {
        String requestScopeAddress = UserInvocationContext.getRequestScopeAddress(id);
        if (requestScopeAddress != null) {
            return requestScopeAddress;
        }

        return address;
    }

    /**
     * INTERNAL
     */
    public void setAddress(String address) {
        this.address = address;
    }

    /**
     * Client application info
     */
    public String getClientInfo() {
        String requestScopeClientInfo = UserInvocationContext.getRequestScopeClientInfo(id);
        if (requestScopeClientInfo != null) {
            return requestScopeClientInfo;
        }

        return clientInfo;
    }

    /**
     * INTERNAL
     */
    public void setClientInfo(String clientInfo) {
        this.clientInfo = clientInfo;
    }

    /**
     * INTERNAL
     * <p>
     * Adds a permission to the joined role. If the joined role already has a permissions that allows more than
     * the added permission, then the added permission is ignored.
     */
    public void addPermission(PermissionType type, String target, int value) {
        RoleDefinition roleWithNewPermission = RoleDefinitionBuilder.create()
                .withPermission(type, target, value)
                .build();
        joinedRole = RoleDefinitionsJoiner.join(joinedRole, roleWithNewPermission);
    }

    /**
     * INTERNAL
     */
    public Integer getPermissionValue(PermissionType type, String target) {
        return PermissionsUtils.getResultingPermissionValue(joinedRole, type, target,
                permissionUndefinedAccessPolicy);
    }

    /**
     * Get permissions by type
     */
    public Map<String, Integer> getPermissionsByType(PermissionType type) {
        PermissionsContainer permissionsContainer = PermissionsUtils.getPermissionsByType(joinedRole, type);
        return Collections.unmodifiableMap(permissionsContainer.getExplicitPermissions());
    }

    /**
     * Check user permission for the screen
     */
    public boolean isScreenPermitted(String windowAlias) {
        return isPermitted(PermissionType.SCREEN, windowAlias);
    }

    /**
     * Check user permission for the entity operation
     */
    public boolean isEntityOpPermitted(MetaClass metaClass, EntityOp entityOp) {
        return isPermitted(PermissionType.ENTITY_OP, PermissionsUtils.getEntityOperationTarget(metaClass, entityOp));
    }

    /**
     * Check user permission for the entity attribute
     */
    public boolean isEntityAttrPermitted(MetaClass metaClass, String property, EntityAttrAccess access) {
        return isPermitted(PermissionType.ENTITY_ATTR,
                PermissionsUtils.getEntityAttributeTarget(metaClass, property),
                access.getId());
    }

    /**
     * Check specific user permission
     */
    public boolean isSpecificPermitted(String name) {
        return isPermitted(PermissionType.SPECIFIC, name);
    }

    /**
     * Check user permission.
     * <br>Same as {@link #isPermitted(com.haulmont.cuba.security.entity.PermissionType, String, int)}
     * with value=1
     * <br>This method makes sense for permission types with two possible values 0,1
     *
     * @param type   permission type
     * @param target permission target:<ul>
     *               <li>screen
     *               <li>entity operation (view, create, update, delete)
     *               <li>entity attribute name
     *               <li>specific permission name
     *               </ul>
     * @return true if permitted, false otherwise
     */
    public boolean isPermitted(PermissionType type, String target) {
        return isPermitted(type, target, 1);
    }

    /**
     * Check user permission for the specified value.
     *
     * @param type   permission type
     * @param target permission target:<ul>
     *               <li>screen
     *               <li>entity operation (view, create, update, delete)
     *               <li>entity attribute name
     *               <li>specific permission name
     *               </ul>
     * @param value  method returns true if the corresponding {@link com.haulmont.cuba.security.entity.Permission}
     *               record contains value equal or greater than specified
     * @return true if permitted, false otherwise
     */
    public boolean isPermitted(PermissionType type, String target, int value) {
        Integer v = PermissionsUtils.getResultingPermissionValue(joinedRole, type, target,
                permissionUndefinedAccessPolicy);
        return (v != null && v >= value);
    }

    /**
     * Get user session attribute. Attribute is a named serializable object bound to session.
     *
     * @param name attribute name. The following names have predefined values:
     *             <ul>
     *             <li>userId - current or substituted user ID</li>
     *             <li>userLogin - current or substituted user login in lower case</li>
     *             </ul>
     * @return attribute value or null if attribute with the given name is not found
     */
    @SuppressWarnings("unchecked")
    @Nullable
    public <T> T getAttribute(String name) {
        if ("userId".equals(name))
            return (T) getCurrentOrSubstitutedUser().getId();
        if ("userLogin".equals(name))
            return (T) getCurrentOrSubstitutedUser().getLoginLowerCase();
        else
            return (T) attributes.get(name);
    }

    /**
     * Remove user session attribute. Attribute is a named serializable object bound to session.
     *
     * @param name attribute name
     */
    public void removeAttribute(String name) {
        attributes.remove(name);
    }

    /**
     * Set user session attribute. Attribute is a named serializable object bound to session.
     *
     * @param name  attribute name
     * @param value attribute value
     */
    public void setAttribute(String name, Serializable value) {
        attributes.put(name, value);
    }

    /**
     * User session attribute names. Attribute is a named serializable object bound to session.
     */
    public Collection<String> getAttributeNames() {
        return new ArrayList<>(attributes.keySet());
    }

    /**
     * Get local attribute. Local attribute is a named object bound to session. Unlike normal user session attributes,
     * local attributes are not passed between tiers and not replicated in cluster.
     *
     * @param name attribute name
     * @return attribute value or null if attribute with the given name is not found
     */
    @SuppressWarnings("unchecked")
    @Nullable
    public <T> T getLocalAttribute(String name) {
        return (T) localAttributes.get(name);
    }

    /**
     * Remove local attribute. Local attribute is a named object bound to session. Unlike normal user session attributes,
     * local attributes are not passed between tiers and not replicated in cluster.
     *
     * @param name attribute name
     */
    public void removeLocalAttribute(String name) {
        localAttributes.remove(name);
    }

    /**
     * Set local attribute. Local attribute is a named object bound to session. Unlike normal user session attributes,
     * local attributes are not passed between tiers and not replicated in cluster.
     *
     * @param name  attribute name
     * @param value attribute value
     */
    public void setLocalAttribute(String name, Object value) {
        localAttributes.put(name, value);
    }

    /**
     * Set local attribute. Local attribute is a named object bound to session. Unlike normal user session attributes,
     * local attributes are not passed between tiers and not replicated in cluster.
     *
     * @param name  attribute name
     * @param value attribute value
     * @return the previous value associated with the specified key, or
     * {@code null} if there was no mapping for the key.
     * (A {@code null} return can also indicate that the map
     * previously associated {@code null} with the key,
     * if the implementation supports null values.)
     */
    public Object setLocalAttributeIfAbsent(String name, Object value) {
        return localAttributes.putIfAbsent(name, value);
    }

    /**
     * Local attribute names. Local attribute is a named object bound to session. Unlike normal user session attributes,
     * local attributes are not passed between tiers and not replicated in cluster.
     */
    public Collection<String> getLocalAttributeNames() {
        return new ArrayList<>(localAttributes.keySet());
    }

    /**
     * System session is created by <code>LoginWorker.loginSystem()</code> for system users like schedulers and JMX.
     * <p>
     * It is not replicated in cluster.
     */
    public boolean isSystem() {
        return system;
    }

    /**
     * Returns an instance of {@link RoleDefinition} interface. It can be used to retrieve information about user permissions.
     * <p>
     * If you need to modify user permissions, use {@code RoleDefBuilder} to construct a suitable role and then
     * apply it using {@link UserSession#setJoinedRole} method.
     */
    public RoleDefinition getJoinedRole() {
        return joinedRole;
    }

    /**
     * Sets {@code joinedRole} to the UserSession. After that user will only have permissions defined in the specified role.
     * <p>
     * Use {@code RoleDefinitionBuilder} to construct a suitable role.
     */
    public void setJoinedRole(RoleDefinition joinedRole) {
        this.joinedRole = joinedRole;
    }

    /**
     * Returns a set of access constraints.
     * If you need to modify access constraints, use {@code AccessConstraintsBuilder} to construct a new set of constraints and then
     * apply it using {@link UserSession#setConstraints(SetOfAccessConstraints)} method.
     */
    public SetOfAccessConstraints getConstraints() {
        return setOfAccessConstraints;
    }

    /**
     * Applies access constraints to the UserSession.
     * <p>
     * Use {@code AccessConstraintsBuilder} to construct a new set of constraints.
     */
    public void setConstraints(SetOfAccessConstraints constraints) {
        this.setOfAccessConstraints = constraints;
    }

    public Access getPermissionUndefinedAccessPolicy() {
        return permissionUndefinedAccessPolicy;
    }

    /**
     * INTERNAL
     *
     * Sets the policy to resolve undefined permission values. Usually the value is taken from the
     * {@code ServerConfig#getDefaultPermissionValuesConfigEnabled}
     */
    public void setPermissionUndefinedAccessPolicy(Access permissionUndefinedAccessPolicy) {
        this.permissionUndefinedAccessPolicy = permissionUndefinedAccessPolicy;
    }

    @Override
    public String toString() {
        return id + " ["
                + user.getLogin() + (substitutedUser == null ? "" : " / " + substitutedUser.getLogin())
                + "]";
    }
}
