/*
 * Copyright (c) 2008-2018 Haulmont.
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

package com.haulmont.cuba.web.gui.components;

import com.haulmont.cuba.gui.ComponentsHelper;
import com.haulmont.cuba.gui.Fragments;
import com.haulmont.cuba.gui.FrameContext;
import com.haulmont.cuba.gui.WindowManager;
import com.haulmont.cuba.gui.components.*;
import com.haulmont.cuba.gui.components.sys.FragmentImplementation;
import com.haulmont.cuba.gui.components.sys.FrameImplementation;
import com.haulmont.cuba.gui.events.sys.UiEventsMulticaster;
import com.haulmont.cuba.gui.screen.ScreenFragment;
import com.haulmont.cuba.gui.screen.UiControllerUtils;
import com.haulmont.cuba.gui.sys.FragmentContextImpl;
import com.haulmont.cuba.web.AppUI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;

import javax.annotation.Nullable;
import java.util.*;
import java.util.stream.Stream;

import static com.haulmont.bali.util.Preconditions.checkNotNullArgument;
import static com.haulmont.cuba.web.gui.components.WebWrapperUtils.toVaadinAlignment;

public class WebFragment extends WebVBoxLayout implements Fragment, FragmentImplementation {

    private static final Logger log = LoggerFactory.getLogger(WebFragment.class);

    protected FrameContext context;
    protected ScreenFragment frameOwner;

    protected Set<Facet> facets = null; // lazily initialized hash set

    protected Map<String, Component> allComponents = new HashMap<>();
    protected WebFrameActionsHolder actionsHolder = new WebFrameActionsHolder(this);

    public WebFragment() {
        component.addActionHandler(actionsHolder);
    }

    @Override
    public void addFacet(Facet facet) {
        checkNotNullArgument(facet);

        if (facets == null) {
            facets = new HashSet<>();
        }

        if (!facets.contains(facet)) {
            facets.add(facet);
            facet.setOwner(this);
        }
    }

    @Nullable
    @Override
    public Facet getFacet(String id) {
        checkNotNullArgument(id);

        if (facets == null) {
            return null;
        }

        return facets.stream()
                .filter(f -> id.equals(f.getId()))
                .findFirst()
                .orElse(null);
    }

    @Override
    public void removeFacet(Facet facet) {
        checkNotNullArgument(facet);

        if (facets != null) {
            if (facets.remove(facet)) {
                facet.setOwner(null);
            }
        }
    }

    @Override
    public Stream<Facet> getFacets() {
        if (facets == null) {
            return Stream.empty();
        }
        return facets.stream();
    }

    @Override
    public void add(Component childComponent, int index) {
        if (childComponent.getParent() != null && childComponent.getParent() != this) {
            throw new IllegalStateException("Component already has parent");
        }

        com.vaadin.ui.Component vComponent = childComponent.unwrapComposition(com.vaadin.ui.Component.class);
        if (ownComponents.contains(childComponent)) {
            int existingIndex = component.getComponentIndex(vComponent);
            if (index > existingIndex) {
                index--;
            }

            remove(childComponent);
        }

        component.addComponent(vComponent, index);
        component.setComponentAlignment(vComponent, toVaadinAlignment(childComponent.getAlignment()));

        // CAUTION here we set this as fragment for nested components
        if (childComponent instanceof BelongToFrame
                && ((BelongToFrame) childComponent).getFrame() == null) {
            ((BelongToFrame) childComponent).setFrame(this);
        } else {
            attachToFrame(childComponent);
        }

        if (index == ownComponents.size()) {
            ownComponents.add(childComponent);
        } else {
            ownComponents.add(index, childComponent);
        }

        childComponent.setParent(this);
    }

    @Override
    protected void attachToFrame(Component childComponent) {
        this.registerComponent(childComponent);
    }

    @Override
    public void setFrame(Frame frame) {
        this.frame = frame;

        if (frame instanceof FrameImplementation) {
            ((FrameImplementation) frame).registerComponent(this);
        }
    }

    @Override
    public ScreenFragment getFrameOwner() {
        return frameOwner;
    }

    @Override
    public FrameContext getContext() {
        return context;
    }

    @Override
    public void setContext(FrameContext ctx) {
        this.context = ctx;
    }

    @Override
    public void registerComponent(Component component) {
        if (component.getId() != null) {
            allComponents.put(component.getId(), component);
        }
    }

    @Override
    public void unregisterComponent(Component component) {
        if (component.getId() != null) {
            allComponents.remove(component.getId());
        }
    }

    @Nullable
    @Override
    public Component getRegisteredComponent(String id) {
        return allComponents.get(id);
    }

    @Nullable
    @Override
    public Component getComponent(String id) {
        return ComponentsHelper.getFrameComponent(this, id);
    }

    @Override
    public boolean isValid() {
        Collection<Component> components = ComponentsHelper.getComponents(this);
        for (Component component : components) {
            if (component instanceof Validatable) {
                Validatable validatable = (Validatable) component;
                if (validatable.isValidateOnCommit() && !validatable.isValid())
                    return false;
            }
        }
        return true;
    }

    @Override
    public void validate() throws ValidationException {
        ComponentsHelper.traverseValidatable(this, Validatable::validate);
    }

    @Override
    public boolean validate(List<Validatable> fields) {
        ValidationErrors errors = new ValidationErrors();

        for (Validatable field : fields) {
            try {
                field.validate();
            } catch (ValidationException e) {
                if (log.isTraceEnabled())
                    log.trace("Validation failed", e);
                else if (log.isDebugEnabled())
                    log.debug("Validation failed: " + e);

                ComponentsHelper.fillErrorMessages(field, e, errors);
            }
        }

        return handleValidationErrors(errors);
    }

    @Override
    public boolean validateAll() {
        ValidationErrors errors = new ValidationErrors();

        ComponentsHelper.traverseValidatable(this, v -> {
            try {
                v.validate();
            } catch (ValidationException e) {
                if (log.isTraceEnabled()) {
                    log.trace("Validation failed", e);
                } else if (log.isDebugEnabled()) {
                    log.debug("Validation failed: " + e);
                }
                ComponentsHelper.fillErrorMessages(v, e, errors);
            }
        });

        return handleValidationErrors(errors);
    }

    protected boolean handleValidationErrors(ValidationErrors errors) {
        if (errors.isEmpty()) {
            return true;
        }

        com.haulmont.cuba.gui.components.Component problemComponent = errors.getFirstComponent();
        if (problemComponent != null) {
            ComponentsHelper.focusComponent(problemComponent);
        }

        return false;
    }

    @Deprecated
    @Override
    public WindowManager getWindowManager() {
        return (WindowManager) UiControllerUtils.getScreenContext(getFrameOwner()).getScreens();
    }

    @Override
    public void addAction(Action action) {
        checkNotNullArgument(action, "action must be non null");

        actionsHolder.addAction(action);
    }

    @Override
    public void addAction(Action action, int index) {
        checkNotNullArgument(action, "action must be non null");

        actionsHolder.addAction(action, index);
    }

    @Override
    public void removeAction(@Nullable Action action) {
        actionsHolder.removeAction(action);
    }

    @Override
    public void removeAction(@Nullable String id) {
        actionsHolder.removeAction(id);
    }

    @Override
    public void removeAllActions() {
        actionsHolder.removeAllActions();
    }

    @Override
    public Collection<Action> getActions() {
        return actionsHolder.getActions();
    }

    @Nullable
    @Override
    public Action getAction(String id) {
        return actionsHolder.getAction(id);
    }

    @Override
    public void setFrameOwner(ScreenFragment controller) {
        this.frameOwner = controller;

        controller.addAfterInitListener(afterInitEvent -> refreshActionsState());
    }

    protected void refreshActionsState() {
        getActions().forEach(Action::refreshState);
    }

    @Override
    public void initUiEventListeners() {
        component.addAttachListener(event -> enableEventListeners());
        component.addDetachListener(event -> disableEventListeners());
    }

    @Override
    public void attached() {
        super.attached();

        FragmentContextImpl context = (FragmentContextImpl) getContext();
        if (context.isManualInitRequired()) {
            if (!context.isInitialized()) {
                Fragments fragments = UiControllerUtils.getScreenContext(frameOwner).getFragments();
                fragments.init(frameOwner);
            }

            UiControllerUtils.fireEvent(frameOwner, ScreenFragment.AttachEvent.class,
                    new ScreenFragment.AttachEvent(frameOwner));
        }
    }

    @Override
    public void detached() {
        super.detached();

        UiControllerUtils.fireEvent(frameOwner, ScreenFragment.DetachEvent.class,
                new ScreenFragment.DetachEvent(frameOwner));
    }

    protected void disableEventListeners() {
        List<ApplicationListener> uiEventListeners = UiControllerUtils.getUiEventListeners(frameOwner);
        if (uiEventListeners != null) {
            AppUI ui = AppUI.getCurrent();
            if (ui != null) {
                UiEventsMulticaster multicaster = ui.getUiEventsMulticaster();

                for (ApplicationListener listener : uiEventListeners) {
                    multicaster.removeApplicationListener(listener);
                }
            }
        }
    }

    protected void enableEventListeners() {
        List<ApplicationListener> uiEventListeners = UiControllerUtils.getUiEventListeners(frameOwner);
        if (uiEventListeners != null) {
            AppUI ui = AppUI.getCurrent();
            if (ui != null) {
                UiEventsMulticaster multicaster = ui.getUiEventsMulticaster();

                for (ApplicationListener listener : uiEventListeners) {
                    multicaster.addApplicationListener(listener);
                }
            }
        }
    }
}