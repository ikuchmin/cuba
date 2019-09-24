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

package com.haulmont.cuba.core.sys;

import com.google.common.collect.Streams;
import com.haulmont.chile.core.datatypes.Datatype;
import com.haulmont.chile.core.datatypes.Datatypes;
import com.haulmont.chile.core.datatypes.impl.EnumClass;
import com.haulmont.chile.core.model.MetaClass;
import com.haulmont.chile.core.model.MetaPropertyPath;
import com.haulmont.cuba.core.entity.*;
import com.haulmont.cuba.core.global.*;
import com.haulmont.cuba.security.entity.ConstraintOperationType;
import com.haulmont.cuba.security.entity.EntityAttrAccess;
import com.haulmont.cuba.security.entity.EntityOp;
import com.haulmont.cuba.security.entity.PermissionType;
import com.haulmont.cuba.security.global.ConstraintData;
import com.haulmont.cuba.security.global.UserSession;
import com.haulmont.cuba.security.group.EntityConstraint;
import com.haulmont.cuba.security.group.PersistenceSecurityService;
import com.haulmont.cuba.security.group.SetOfEntityConstraints;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.groovy.runtime.MethodClosure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.text.ParseException;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.haulmont.cuba.security.entity.ConstraintOperationType.ALL;
import static com.haulmont.cuba.security.entity.ConstraintOperationType.CUSTOM;
import static java.lang.String.format;

@Component(Security.NAME)
public class SecurityImpl implements Security {
    private final Logger log = LoggerFactory.getLogger(SecurityImpl.class);

    @Inject
    protected UserSessionSource userSessionSource;

    @Inject
    protected Metadata metadata;

    @Inject
    protected MetadataTools metadataTools;

    @Inject
    protected ExtendedEntities extendedEntities;

    @Inject
    protected Scripting scripting;

    @Inject
    protected PersistenceSecurityService persistenceSecurityService;

    @Override
    public boolean isScreenPermitted(String windowAlias) {
        return userSessionSource.getUserSession().isScreenPermitted(windowAlias);
    }

    @Override
    public boolean isEntityOpPermitted(MetaClass metaClass, EntityOp entityOp) {
        MetaClass originalMetaClass = extendedEntities.getOriginalMetaClass(metaClass);
        if (originalMetaClass != null) {
            metaClass = originalMetaClass;
        }

        return userSessionSource.getUserSession().isEntityOpPermitted(metaClass, entityOp);
    }

    @Override
    public boolean isEntityOpPermitted(Class<?> entityClass, EntityOp entityOp) {
        MetaClass metaClass = metadata.getSession().getClassNN(entityClass);
        return isEntityOpPermitted(metaClass, entityOp);
    }

    @Override
    public boolean isEntityAttrPermitted(MetaClass metaClass, String property, EntityAttrAccess access) {
        MetaPropertyPath mpp = metadataTools.resolveMetaPropertyPath(metaClass, property);
        return mpp != null && isEntityAttrPermitted(metaClass, mpp, access);
    }

    @Override
    public boolean isEntityAttrPermitted(Class<?> entityClass, String property, EntityAttrAccess access) {
        MetaClass metaClass = metadata.getSession().getClassNN(entityClass);
        return isEntityAttrPermitted(metaClass, property, access);
    }

    @Override
    public boolean isEntityAttrReadPermitted(MetaClass metaClass, String propertyPath) {
        MetaPropertyPath mpp = metadataTools.resolveMetaPropertyPath(metaClass, propertyPath);
        return mpp != null && isEntityAttrReadPermitted(mpp);
    }

    @Override
    public boolean isEntityAttrUpdatePermitted(MetaClass metaClass, String propertyPath) {
        MetaPropertyPath mpp = metadataTools.resolveMetaPropertyPath(metaClass, propertyPath);
        return mpp != null && isEntityAttrUpdatePermitted(mpp);
    }

    @Override
    public boolean isSpecificPermitted(String name) {
        return userSessionSource.getUserSession().isSpecificPermitted(name);
    }

    @Override
    public void checkSpecificPermission(String name) {
        if (!isSpecificPermitted(name))
            throw new AccessDeniedException(PermissionType.SPECIFIC, name);
    }

    @Override
    public boolean isEntityAttrReadPermitted(MetaPropertyPath mpp) {
        MetaClass propertyMetaClass = metadata.getTools().getPropertyEnclosingMetaClass(mpp);
        return isEntityOpPermitted(propertyMetaClass, EntityOp.READ)
                && isEntityAttrPermitted(propertyMetaClass, mpp, EntityAttrAccess.VIEW);
    }

    protected boolean isEntityAttrPermitted(MetaClass metaClass, MetaPropertyPath propertyPath, EntityAttrAccess access) {
        MetaClass originalMetaClass = extendedEntities.getOriginalMetaClass(metaClass);
        if (originalMetaClass != null) {
            metaClass = originalMetaClass;
        }

        return userSessionSource.getUserSession()
                .isEntityAttrPermitted(metaClass, propertyPath.getMetaProperty().getName(), access);
    }

    @Override
    public boolean isEntityAttrUpdatePermitted(MetaPropertyPath mpp) {
        MetaClass propertyMetaClass = metadata.getTools().getPropertyEnclosingMetaClass(mpp);

        if (metadata.getTools().isEmbeddable(propertyMetaClass)) {
            return isEntityOpPermitted(propertyMetaClass, EntityOp.UPDATE)
                    && isEntityAttrPermitted(propertyMetaClass, mpp, EntityAttrAccess.MODIFY)
                    && isEntityOpPermitted(mpp.getMetaClass(), EntityOp.UPDATE);
        }

        return (isEntityOpPermitted(propertyMetaClass, EntityOp.CREATE)
                || isEntityOpPermitted(propertyMetaClass, EntityOp.UPDATE))
                && isEntityAttrPermitted(propertyMetaClass, mpp, EntityAttrAccess.MODIFY);
    }

    @Override
    public boolean isPermitted(Entity entity, EntityOp operation) {
        return persistenceSecurityService.isPermitted(entity, operation);
    }

    @Override
    public boolean isPermitted(Entity entity, ConstraintOperationType operationType) {
        for (EntityOp entityOp : operationType.toEntityOps()) {
            if (!persistenceSecurityService.isPermitted(entity,entityOp)) {
                return false;
            }
        }
        return true;
//        return isPermitted(entity,
//                constraint -> {
//                    ConstraintOperationType operationType = constraint.getOperationType();
//                    return constraint.getCheckType().memory()
//                            && (
//                            (targetOperationType == ALL && operationType != CUSTOM)
//                                    || operationType == targetOperationType
//                                    || operationType == ALL
//                    );
//                });
    }

    @Override
    public boolean isPermitted(Entity entity, String customCode) {
        return persistenceSecurityService.isPermitted(entity, customCode);
//        return isPermitted(entity,
//                constraint -> customCode.equals(constraint.getCode()) && constraint.getCheckType().memory());
    }



    @Override
    public boolean hasConstraints(MetaClass metaClass) {
        return getConstraints(metaClass).findAny().isPresent();
    }

    @Override
    public boolean hasInMemoryConstraints(MetaClass metaClass, ConstraintOperationType... operationTypes) {
        final Set<EntityOp> entityOperations = Stream.of(operationTypes)
                .flatMap(o -> o.toEntityOps().stream())
                .collect(Collectors.toSet());

        return getConstraints(metaClass)
                .anyMatch(c -> c.isInMemory() && entityOperations.contains(c.getOperation()));
    }

    @Override
    public Object evaluateConstraintScript(Entity entity, String groovyScript) {
        return persistenceSecurityService.evaluateConstraintScript(entity, groovyScript);
    }

    protected Stream<EntityConstraint> getConstraints(MetaClass metaClass) {
        UserSession userSession = userSessionSource.getUserSession();
        MetaClass mainMetaClass = extendedEntities.getOriginalOrThisMetaClass(metaClass);

        SetOfEntityConstraints setOfConstraints = userSession.getConstraints();

        Stream<EntityConstraint> constraints = setOfConstraints.findConstraintsByEntity(mainMetaClass.getName());
        for (MetaClass parent : mainMetaClass.getAncestors()) {
            constraints = Streams.concat(constraints, setOfConstraints.findConstraintsByEntity(parent.getName()));
        }
        return constraints;
    }


    //TODO: refactor it
    @Override
    public Object evaluateConstraintScript(Entity entity, String groovyScript) {
        Map<String, Object> context = new HashMap<>();
        context.put("__entity__", entity);
        context.put("parse", new MethodClosure(this, "parseValue"));
        context.put("userSession", userSessionSource.getUserSession());
        fillGroovyConstraintsContext(context);
        return scripting.evaluateGroovy(groovyScript.replace("{E}", "__entity__"), context);
    }

    /**
     * Override if you need specific context variables in Groovy constraints.
     *
     * @param context passed to Groovy evaluator
     */
    protected void fillGroovyConstraintsContext(Map<String, Object> context) {
    }

    @SuppressWarnings("unused")
    protected Object parseValue(Class<?> clazz, String string) {
        try {
            if (Entity.class.isAssignableFrom(clazz)) {
                Object entity = metadata.create(clazz);
                if (entity instanceof BaseIntegerIdEntity) {
                    ((BaseIntegerIdEntity) entity).setId(Integer.valueOf(string));
                } else if (entity instanceof BaseLongIdEntity) {
                    ((BaseLongIdEntity) entity).setId(Long.valueOf(string));
                } else if (entity instanceof BaseStringIdEntity) {
                    ((BaseStringIdEntity) entity).setId(string);
                } else if (entity instanceof BaseIdentityIdEntity) {
                    ((BaseIdentityIdEntity) entity).setId(IdProxy.of(Long.valueOf(string)));
                } else if (entity instanceof BaseIntIdentityIdEntity) {
                    ((BaseIntIdentityIdEntity) entity).setId(IdProxy.of(Integer.valueOf(string)));
                } else if (entity instanceof HasUuid) {
                    ((HasUuid) entity).setUuid(UUID.fromString(string));
                }
                return entity;
            } else if (EnumClass.class.isAssignableFrom(clazz)) {
                //noinspection unchecked
                Enum parsedEnum = Enum.valueOf((Class<Enum>) clazz, string);
                return parsedEnum;
            } else {
                Datatype datatype = Datatypes.get(clazz);
                return datatype != null ? datatype.parse(string) : string;
            }
        } catch (ParseException | IllegalArgumentException e) {
            log.error("Could not parse a value in constraint. Class [{}], value [{}].", clazz, string, e);
            throw new RowLevelSecurityException(format("Could not parse a value in constraint. Class [%s], value [%s]. " +
                    "See the log for details.", clazz, string), null);
        }
    }
}