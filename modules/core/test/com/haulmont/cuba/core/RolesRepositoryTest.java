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

package com.haulmont.cuba.core;

import com.haulmont.cuba.core.global.AppBeans;
import com.haulmont.cuba.core.global.Metadata;
import com.haulmont.cuba.security.app.role.FullAccessRoleDefinition;
import com.haulmont.cuba.security.app.role.RolesRepository;
import com.haulmont.cuba.security.entity.*;
import com.haulmont.cuba.security.role.*;
import com.haulmont.cuba.testsupport.TestContainer;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.*;

public class RolesRepositoryTest {

    protected RolesRepository rolesRepository;
    protected Metadata metadata;

    @ClassRule
    public static TestContainer cont = TestContainer.Common.INSTANCE;

    @Before
    public void setUp() throws Exception {
        rolesRepository = AppBeans.get(RolesRepository.NAME);
        metadata = cont.metadata();
    }

    @After
    public void cleanUp() {
        //need to unregister default role because all new users from another tests will have this role
        //but there is no special method for unregister so we have to register new role with the same name
        rolesRepository.registerRole(new TestRole() {
            @Override
            public boolean isDefault() {
                return false;
            }
        });
    }

//    @Test
//    public void testGetRoleDefs() {
//        UserRole userRole = metadata.create(UserRole.class);
//        userRole.setRoleName("Administrators");
//
//        assertNull(userRole.getRoleDefinition());
//
//        Collection<RoleDefinition> roleDefinitions = rolesRepository.getRoleDefinitions(Collections.singletonList(userRole));
//
//        assertNotNull(roleDefinitions);
//        assertEquals(1, roleDefinitions.size());
//
//        RoleDefinition roleDefinition = roleDefinitions.iterator().next();
//
//        assertEquals("Administrators", roleDefinition.getName());
//        assertNotNull(userRole.getRoleDefinition());
//        assertEquals(userRole.getRoleDefinition(), roleDefinition);
//    }

    @Test
    public void testGetRoleDefByName() {
        RoleDefinition roleDefinition = rolesRepository.getRoleDefinitionByName("NonexistentRole");

        assertNull(roleDefinition);

        roleDefinition = rolesRepository.getRoleDefinitionByName(FullAccessRoleDefinition.ROLE_NAME);

        assertNotNull(roleDefinition);
    }

    @Test
    public void testRegisterRoleAndGetDefaultRoles() {
        RoleDefinition testRole = new TestRole();
        rolesRepository.registerRole(testRole);

        assertNotNull(rolesRepository.getRoleDefinitionByName("TestRole"));

        Map<String, Role> defaultRoles = rolesRepository.getDefaultRoles();

        assertNotNull(defaultRoles);
        assertEquals(1, defaultRoles.size());
        assertTrue(defaultRoles.containsKey("TestRole"));
    }

    @Test
    public void testGetRoleWithPermissions() {
        RoleDefinition roleDefinition = new TestRole();

        Role roleObj = rolesRepository.getRoleWithPermissions(roleDefinition);

        assertNotNull(roleObj);
        assertEquals("TestRole", roleObj.getName());
        assertEquals(RoleType.STANDARD, roleObj.getType());
        assertTrue(roleObj.getDefaultRole());
        assertTrue(roleObj.isPredefined());
    }

    @Test
    public void testGetPermissions() {
        RoleDefinition roleDefinition = new TestRole() {
            @Override
            public String getName() {
                return "TestRole2";
            }

            @Override
            public SpecificPermissionsContainer specificPermissions() {
                SpecificPermissionsContainer permissions = new SpecificPermissionsContainer();
                permissions.getExplicitPermissions().put("specPermission1", 1);
                permissions.getExplicitPermissions().put("specPermission2", 0);
                return permissions;
            }

            @Override
            public boolean isDefault() {
                return false;
            }
        };

        rolesRepository.registerRole(roleDefinition);

        Collection<Permission> permissions = rolesRepository.getPermissions("TestRole2", PermissionType.SPECIFIC);

        assertNotNull(permissions);
        assertEquals(2, permissions.size());
        assertTrue(permissions.stream().anyMatch(p -> "specPermission1".equals(p.getTarget()) && p.getValue() == 1));
        assertTrue(permissions.stream().anyMatch(p -> "specPermission2".equals(p.getTarget()) && p.getValue() == 0));
    }

    protected class TestRole implements RoleDefinition {

        @Override
        public String getName() {
            return "TestRole";
        }

        @Override
        public EntityPermissionsContainer entityPermissions() {
            return new EntityPermissionsContainer();
        }

        @Override
        public EntityAttributePermissionsContainer entityAttributePermissions() {
            return new EntityAttributePermissionsContainer();
        }

        @Override
        public SpecificPermissionsContainer specificPermissions() {
            return new SpecificPermissionsContainer();
        }

        @Override
        public ScreenPermissionsContainer screenPermissions() {
            return new ScreenPermissionsContainer();
        }

        @Override
        public ScreenElementsPermissionsContainer screenElementsPermissions() {
            return new ScreenElementsPermissionsContainer();
        }

        @Override
        public boolean isDefault() {
            return true;
        }
    }
}
