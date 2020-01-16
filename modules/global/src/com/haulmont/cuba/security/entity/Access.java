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

package com.haulmont.cuba.security.entity;

import com.haulmont.chile.core.datatypes.impl.EnumClass;

public enum Access implements EnumClass<Integer>, HasSecurityAccessValue {
    DENY(0),
    ALLOW(1);

    private int id;

    Access(int id) {
        this.id = id;
    }

    public Integer getId() {
        return id;
    }

    public static Access fromId(Integer id) {
        if (id == null) return null;
        switch (id) {
            case 0: return DENY;
            case 1: return ALLOW;
            default: return null;
        }
    }
}
