/*
 * Copyright (c) 2008-2017 Haulmont.
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

package com.haulmont.cuba.gui.app.security.constraintloc.edit;

import com.haulmont.cuba.core.app.ConstraintLocalizationService;
import com.haulmont.cuba.core.global.GlobalConfig;
import com.haulmont.cuba.core.global.UserSessionSource;
import com.haulmont.cuba.gui.components.AbstractEditor;
import com.haulmont.cuba.gui.components.LookupField;
import com.haulmont.cuba.gui.components.ResizableTextArea;
import com.haulmont.cuba.gui.components.TextField;
import com.haulmont.cuba.security.entity.LocalizedConstraintMessage;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.Locale;
import java.util.Map;

public class ConstraintLocalizationEdit extends AbstractEditor<LocalizedConstraintMessage> {
    @Named("fieldGroup.operationType")
    protected LookupField operationTypeField;

    @Inject
    protected LookupField localesSelect;

    @Inject
    protected TextField caption;

    @Inject
    protected ResizableTextArea message;

    @Inject
    protected GlobalConfig globalConfig;

    @Inject
    protected UserSessionSource userSessionSource;

    @Inject
    protected ConstraintLocalizationService constraintLocalizationService;

    protected boolean internalUpdate = false;

    @Override
    protected void postInit() {
        operationTypeField.setTextInputAllowed(false);

        initLocalesField();
        initCaptionField();
        initMessageField();
    }

    protected void initLocalesField() {
        Map<String, Locale> locales = globalConfig.getAvailableLocales();
        localesSelect.setOptionsMap(locales);

        localesSelect.addValueChangeListener(e -> {
            Locale selectedLocale = (Locale) e.getValue();
            internalUpdate = true;
            caption.setValue(constraintLocalizationService.getLocalizationCaption(getItem(), selectedLocale));
            message.setValue(constraintLocalizationService.getLocalizationMessage(getItem(), selectedLocale));
            internalUpdate = false;
        });

        localesSelect.setValue(userSessionSource.getLocale());
    }

    protected void initCaptionField() {
        caption.addValueChangeListener(e -> {
            if (!internalUpdate) {
                Locale selectedLocale = localesSelect.getValue();
                String messages = constraintLocalizationService.putLocalizationCaption(getItem(),
                        selectedLocale, (String) e.getValue());
                getItem().setMessages(messages);
            }
        });
    }

    protected void initMessageField() {
        message.addValueChangeListener(e -> {
            if (!internalUpdate) {
                Locale selectedLocale = localesSelect.getValue();
                String messages = constraintLocalizationService.putLocalizationMessage(getItem(),
                        selectedLocale, (String) e.getValue());
                getItem().setMessages(messages);
            }
        });
    }
}
