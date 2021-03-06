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

package com.haulmont.cuba.security.app.role.annotation;

import com.haulmont.cuba.security.entity.EntityOp;
import com.haulmont.cuba.security.role.RoleDefinition;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation must be placed on the {@link RoleDefinition#entityPermissions()} method of the role definition. The
 * annotation defines default permissions for entity access operations.
 *
 * <p>Example:
 *
 * <pre>
 *     &#064;DefaultEntityAccess(
 *              allow = {EntityOp.READ},
 *              deny = {EntityOp.DELETE, EntityOp.UPDATE})
 * </pre>
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface DefaultEntityAccess {

    EntityOp[] deny() default {};

    EntityOp[] allow() default {};
}
