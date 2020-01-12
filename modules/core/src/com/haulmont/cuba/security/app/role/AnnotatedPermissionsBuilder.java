/*
 * Copyright (c) 2008-2019 Haulmont.
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
 */

package com.haulmont.cuba.security.app.role;

import com.google.common.base.Strings;
import com.haulmont.chile.core.model.MetaClass;
import com.haulmont.cuba.core.global.Metadata;
import com.haulmont.cuba.security.app.role.annotation.*;
import com.haulmont.cuba.security.entity.Access;
import com.haulmont.cuba.security.entity.EntityAttrAccess;
import com.haulmont.cuba.security.entity.EntityOp;
import com.haulmont.cuba.security.entity.RoleType;
import com.haulmont.cuba.security.role.*;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.function.BiFunction;

/**
 * INTERNAL
 * <p>
 * Helps construct permissions for roles defined using annotations.
 */
@Component(AnnotatedPermissionsBuilder.NAME)
public class AnnotatedPermissionsBuilder {
    public static final String NAME = "cuba_AnnotatedPermissionsBuilder";

    private static final String ENTITY_ACCESS_METHOD_NAME = "entityPermissions";
    private static final String ENTITY_ATTR_ACCESS_METHOD_NAME = "entityAttributePermissions";
    private static final String SPECIFIC_ACCESS_METHOD_NAME = "specificPermissions";
    private static final String SCREEN_ACCESS_METHOD_NAME = "screenPermissions";
    private static final String SCREEN_ELEMENTS_ACCESS_METHOD_NAME = "screenElementsPermissions";

    @Inject
    protected Metadata metadata;

    public EntityPermissionsContainer buildEntityAccessPermissions(RoleDefinition role) {
        return (EntityPermissionsContainer) processAnnotationsInternal(role,
                EntityAccess.class,
                DefaultEntityAccess.class,
                ENTITY_ACCESS_METHOD_NAME,
                (annotation, permissions) -> processEntityAccessAnnotation((EntityAccess) annotation,
                        (EntityPermissionsContainer) permissions),
                (annotation, permissions) -> processDefaultEntityAccessAnnotation((DefaultEntityAccess) annotation,
                        (EntityPermissionsContainer) permissions));
    }

    public EntityAttributePermissionsContainer buildEntityAttributeAccessPermissions(RoleDefinition role) {

        return (EntityAttributePermissionsContainer) processAnnotationsInternal(role,
                EntityAttributeAccess.class,
                DefaultEntityAttributeAccess.class,
                ENTITY_ATTR_ACCESS_METHOD_NAME,
                (annotation, permissions) -> processEntityAttributeAccessAnnotation((EntityAttributeAccess) annotation,
                        (EntityAttributePermissionsContainer) permissions),
                (annotation, permissions) -> processDefaultEntityAttributeAccessAnnotation(
                        (DefaultEntityAttributeAccess) annotation,
                        (EntityAttributePermissionsContainer) permissions));
    }

    public SpecificPermissionsContainer buildSpecificPermissions(RoleDefinition role) {
        return (SpecificPermissionsContainer) processAnnotationsInternal(role,
                SpecificAccess.class,
                DefaultSpecificAccess.class,
                SPECIFIC_ACCESS_METHOD_NAME,
                (annotation, permissions) -> processSpecificAccessAnnotation((SpecificAccess) annotation,
                        (SpecificPermissionsContainer) permissions),
                (annotation, permissions) -> processDefaultSpecificAccessAnnotation((DefaultSpecificAccess) annotation,
                        (SpecificPermissionsContainer) permissions)
        );
    }

    public ScreenPermissionsContainer buildScreenPermissions(RoleDefinition role) {
        return (ScreenPermissionsContainer) processAnnotationsInternal(role,
                ScreenAccess.class,
                DefaultScreenAccess.class,
                SCREEN_ACCESS_METHOD_NAME,
                (annotation, permissions) -> processScreenAccessAnnotation((ScreenAccess) annotation,
                        (ScreenPermissionsContainer) permissions),
                (annotation, permissions) -> processDefaultScreenAccessAnnotation((DefaultScreenAccess) annotation,
                        (ScreenPermissionsContainer) permissions));
    }

    public ScreenElementsPermissionsContainer buildScreenElementsPermissions(RoleDefinition role) {
        return (ScreenElementsPermissionsContainer) processAnnotationsInternal(role,
                ScreenElementAccess.class,
                null,
                SCREEN_ELEMENTS_ACCESS_METHOD_NAME,
                (annotation, permissions) -> processScreenElementAccessAnnotation((ScreenElementAccess) annotation,
                        (ScreenElementsPermissionsContainer) permissions),
                (annotation, permissions) -> permissions);
    }

    ;

    public String getNameFromAnnotation(RoleDefinition role) {
        Role annotation = getPredefinedRoleAnnotationNN(role);

        return annotation.name();
    }

    public String getSecurityScopeFromAnnotation(RoleDefinition role) {
        Role annotation = getPredefinedRoleAnnotationNN(role);

        return annotation.securityScope();
    }

    public String getDescriptionFromAnnotation(RoleDefinition role) {
        Role annotation = getPredefinedRoleAnnotationNN(role);

        return annotation.description();
    }

    public RoleType getTypeFromAnnotation(RoleDefinition role) {
        Role annotation = getPredefinedRoleAnnotationNN(role);

        return annotation.type();
    }

    public boolean getIsDefaultFromAnnotation(RoleDefinition role) {
        Role annotation = getPredefinedRoleAnnotationNN(role);

        return annotation.isDefault();
    }

    protected Role getPredefinedRoleAnnotationNN(RoleDefinition role) {
        Role annotation = role.getClass().getAnnotation(Role.class);
        if (annotation == null) {
            throw new IllegalArgumentException("The class must have Role annotation.");
        }
        return annotation;
    }

    protected EntityAttributePermissionsContainer processEntityAttributeAccessAnnotation(
            EntityAttributeAccess annotation,
            EntityAttributePermissionsContainer permissions) {
        Class entityClass = annotation.target();
        MetaClass metaClass = metadata.getClassNN(entityClass);
        String[] deny = annotation.deny();
        String[] allow = annotation.modify();
        String[] readOnly = annotation.view();

        for (String property : deny) {
            String target = PermissionsUtils.getEntityAttributeTarget(metaClass, property);
            Integer permissionValue = EntityAttrAccess.DENY.getId();
            permissions.getExplicitPermissions().put(target, permissionValue);
            String extendedTarget = PermissionsUtils.evaluateExtendedEntityTarget(target);
            if (!Strings.isNullOrEmpty(extendedTarget)) {
                permissions.getExplicitPermissions().put(extendedTarget, permissionValue);
            }
        }

        for (String property : allow) {
            String target = PermissionsUtils.getEntityAttributeTarget(metaClass, property);
            Integer permissionValue = EntityAttrAccess.MODIFY.getId();
            permissions.getExplicitPermissions().put(target, permissionValue);
            String extendedTarget = PermissionsUtils.evaluateExtendedEntityTarget(target);
            if (!Strings.isNullOrEmpty(extendedTarget)) {
                permissions.getExplicitPermissions().put(extendedTarget, permissionValue);
            }
        }

        for (String property : readOnly) {
            String target = PermissionsUtils.getEntityAttributeTarget(metaClass, property);
            Integer permissionValue = EntityAttrAccess.VIEW.getId();
            permissions.getExplicitPermissions().put(target, permissionValue);
            String extendedTarget = PermissionsUtils.evaluateExtendedEntityTarget(target);
            if (!Strings.isNullOrEmpty(extendedTarget)) {
                permissions.getExplicitPermissions().put(extendedTarget, permissionValue);
            }
        }
        return permissions;
    }

    protected EntityAttributePermissionsContainer processDefaultEntityAttributeAccessAnnotation(
            DefaultEntityAttributeAccess annotation,
            EntityAttributePermissionsContainer permissions) {
        permissions.setDefaultEntityAttributeAccess(annotation.value());
        return permissions;
    }

    protected EntityPermissionsContainer processEntityAccessAnnotation(EntityAccess annotation,
                                                                       EntityPermissionsContainer permissions) {
        Class entityClass = annotation.target();
        MetaClass metaClass = metadata.getClassNN(entityClass);
        EntityOp[] deny = annotation.deny();
        EntityOp[] allow = annotation.allow();

        for (EntityOp entityOp : deny) {
            String target = PermissionsUtils.getEntityOperationTarget(metaClass, entityOp);
            Integer permissionValue = Access.DENY.getId();
            permissions.getExplicitPermissions().put(target, permissionValue);
            String extendedTarget = PermissionsUtils.evaluateExtendedEntityTarget(target);
            if (!Strings.isNullOrEmpty(extendedTarget)) {
                permissions.getExplicitPermissions().put(extendedTarget, permissionValue);
            }
        }

        for (EntityOp entityOp : allow) {
            String target = PermissionsUtils.getEntityOperationTarget(metaClass, entityOp);
            Integer permissionValue = Access.ALLOW.getId();
            permissions.getExplicitPermissions().put(target, permissionValue);
            String extendedTarget = PermissionsUtils.evaluateExtendedEntityTarget(target);
            if (!Strings.isNullOrEmpty(extendedTarget)) {
                permissions.getExplicitPermissions().put(extendedTarget, permissionValue);
            }
        }

        return permissions;
    }

    protected EntityPermissionsContainer processDefaultEntityAccessAnnotation(DefaultEntityAccess annotation,
                                                                              EntityPermissionsContainer permissions) {
        permissions.setDefaultEntityCreateAccess(annotation.create());
        permissions.setDefaultEntityReadAccess(annotation.read());
        permissions.setDefaultEntityUpdateAccess(annotation.update());
        permissions.setDefaultEntityDeleteAccess(annotation.delete());
        return permissions;
    }

    protected SpecificPermissionsContainer processSpecificAccessAnnotation(SpecificAccess annotation,
                                                                           SpecificPermissionsContainer permissions) {
        String target = annotation.target();
        Access access = annotation.access();

        if (Strings.isNullOrEmpty(target)) {
            return permissions;
        }

        permissions.getExplicitPermissions().put(target, access.getId());

        return permissions;
    }

    protected SpecificPermissionsContainer processDefaultSpecificAccessAnnotation(
            DefaultSpecificAccess annotation,
            SpecificPermissionsContainer permissions) {
        permissions.setDefaultSpecificAccess(annotation.value());
        return permissions;
    }

    protected ScreenPermissionsContainer processScreenAccessAnnotation(ScreenAccess annotation,
                                                                       ScreenPermissionsContainer permissions) {
        String[] deny = annotation.deny();
        String[] allow = annotation.allow();

        for (String screen : deny) {
            permissions.getExplicitPermissions().put(screen, Access.DENY.getId());
        }

        for (String screen : allow) {
            permissions.getExplicitPermissions().put(screen, Access.ALLOW.getId());
        }

        return permissions;
    }

    protected ScreenPermissionsContainer processDefaultScreenAccessAnnotation(DefaultScreenAccess annotation,
                                                                              ScreenPermissionsContainer permissions) {
        permissions.setDefaultScreenAccess(annotation.value());
        return permissions;
    }

    protected ScreenElementsPermissionsContainer processScreenElementAccessAnnotation(
            ScreenElementAccess annotation,
            ScreenElementsPermissionsContainer permissions) {
        String screen = annotation.screen();
        String[] deny = annotation.deny();
        String[] allow = annotation.allow();

        if (Strings.isNullOrEmpty(screen)) {
            return permissions;
        }

        for (String component : deny) {
            String target = PermissionsUtils.getScreenElementTarget(screen, component);
            permissions.getExplicitPermissions().put(target, Access.DENY.getId());
        }

        for (String component : allow) {
            String target = PermissionsUtils.getScreenElementTarget(screen, component);
            permissions.getExplicitPermissions().put(target, Access.ALLOW.getId());
        }

        return permissions;

    }

    protected PermissionsContainer processAnnotationsInternal(
            Object role,
            Class<? extends Annotation> explicitAccessAnnotationClass,
            @Nullable Class<? extends Annotation> defaultAccessAnnotationClass,
            String methodName,
            BiFunction<Object, PermissionsContainer, PermissionsContainer> explicitAccessBiFunction,
            BiFunction<Object, PermissionsContainer, PermissionsContainer> defaultAccessBiFunction) {
        if (role == null) {
            return null;
        }

        try {
            Method method = role.getClass().getMethod(methodName);
            Object[] explicitAccessAnnotations = method.getAnnotationsByType(explicitAccessAnnotationClass);
            PermissionsContainer permissionsContainer = createPermissionsByMethodName(methodName);

            for (Object annotation : explicitAccessAnnotations) {
                permissionsContainer = explicitAccessBiFunction.apply(annotation, permissionsContainer);
            }

            if (defaultAccessAnnotationClass != null) {
                Annotation defaultAccessAnnotation = method.getAnnotation(defaultAccessAnnotationClass);
                if (defaultAccessAnnotation != null) {
                    permissionsContainer = defaultAccessBiFunction.apply(defaultAccessAnnotation, permissionsContainer);
                }
            }

            return permissionsContainer;

        } catch (NoSuchMethodException e) {
            throw new IllegalArgumentException("No such method: " + methodName);
        }
    }

    protected PermissionsContainer createPermissionsByMethodName(String methodName) {
        switch (methodName) {
            case ENTITY_ACCESS_METHOD_NAME:
                return new EntityPermissionsContainer();
            case ENTITY_ATTR_ACCESS_METHOD_NAME:
                return new EntityAttributePermissionsContainer();
            case SPECIFIC_ACCESS_METHOD_NAME:
                return new SpecificPermissionsContainer();
            case SCREEN_ACCESS_METHOD_NAME:
                return new ScreenPermissionsContainer();
            case SCREEN_ELEMENTS_ACCESS_METHOD_NAME:
                return new ScreenElementsPermissionsContainer();
            default:
                throw new IllegalArgumentException("No such method: " + methodName);

        }
    }
}
