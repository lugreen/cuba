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
package com.haulmont.cuba.gui.components;

public interface PopupButton extends Component.ActionsHolder, Component.HasCaption, Component.BelongToFrame,
        Component.HasIcon, Component.Focusable {

    String NAME = "popupButton";

    /**
     * @return true if popup is opened
     */
    boolean isPopupVisible();
    /**
     * Open or close popup panel.
     *
     * @param popupVisible whether open or close popup panel.
     */
    void setPopupVisible(boolean popupVisible);

    /**
     * Set menu width.
     *
     * @param width new menu width
     */
    void setMenuWidth(String width);
    /**
     * @return menu width
     */
    float getMenuWidth();
    /**
     * @return one of width units: {@link #UNITS_PIXELS}, {@link #UNITS_PERCENTAGE}
     */
    int getMenuWidthUnits();

    /**
     * @return whether to close menu automatically after action trigger or not
     */
    boolean isAutoClose();
    /**
     * Set menu automatic close mode.
     *
     * @param autoClose whether to close menu automatically after action trigger or not
     */
    void setAutoClose(boolean autoClose);

    /**
     * Set show icons for action buttons
     */
    void setShowActionIcons(boolean showActionIcons);
    /**
     * Return show icons for action buttons
     */
    boolean isShowActionIcons();
}