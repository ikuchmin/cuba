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
 */

package com.haulmont.bali.events;

import javax.annotation.concurrent.NotThreadSafe;
import java.util.*;
import java.util.function.BiConsumer;

/**
 * Generic Event router with lazily initialized events map.
 */
@NotThreadSafe
public final class EventRouter {
    // Map with listener classes and listener lists
    // Lists are created on demand
    private Map<Class, List<Object>> events = null;

    public <L, E> void fireEvent(Class<L> listenerClass, BiConsumer<L, E> invoker, E event) {
        if (events != null) {
            @SuppressWarnings("unchecked")
            List<L> listeners = (List<L>) events.get(listenerClass);
            if (listeners != null) {
                for (Object listenerEntry : listeners.toArray()) {
                    @SuppressWarnings("unchecked")
                    L listener = (L) listenerEntry;
                    invoker.accept(listener, event);
                }
            }
        }
    }

    public <L> void addListener(Class<L> listenerClass, L listener) {
        if (events == null) {
            events = new IdentityHashMap<>();
        }

        List<Object> listeners = events.computeIfAbsent(listenerClass, clazz -> new ArrayList<>());
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public <L> void removeListener(Class<L> listenerClass, L listener) {
        if (events != null) {
            events.getOrDefault(listenerClass, Collections.emptyList())
                    .remove(listener);
        }
    }

    public <L> boolean hasListeners(Class<L> listenerClass) {
        if (events != null) {
            List<Object> listeners = events.getOrDefault(listenerClass, Collections.emptyList());
            return !listeners.isEmpty();
        }

        return false;
    }
}