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

package com.haulmont.cuba.web.sys;

import com.vaadin.server.ClientConnector;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * If this annotation is present on a {@link ClientConnector} class, web resources referenced to this class
 * will be served by the specified URLs from WebJars declared as compile dependencies.
 * <p>
 * Example of a WebJar URL: <code>"jquery/1.12.4/jquery.min.js"</code>
 * <p>
 * To override a web resource, that was previously referenced by this annotation, put new files in the following path:
 * <code>VAADIN/webjars/resourcename/version/resourcefile</code>.
 * <p>
 * Example: <code>VAADIN/webjars/jquery/1.12.4/jquery.min.js</code>
 * <p>
 * One more opportunity is the managing a version of a web resource by a web-app property. To declare that version should
 * be resolved from the web-app.properties use a URL like this: <code>jquery/${webjar.jquery.customVersion}</code>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface WebJarResource {

    /**
     * Web resources to load before initializing the client-side connector.
     *
     * @return an array of web resources WebJar URLs.
     */
    String[] value();
}
