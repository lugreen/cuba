/*
 * Copyright (c) 2011 Haulmont Technology Ltd. All Rights Reserved.
 * Haulmont Technology proprietary and confidential.
 * Use is subject to license terms.
 */

package com.haulmont.cuba.core.app;

import com.haulmont.cuba.core.global.Logging;
import com.haulmont.cuba.core.global.SupportedByClient;

/**
 * Service interface for integration testing. Don't use it in application code!
 *
 * @author krivopustov
 * @version $Id$
 */
public interface TestingService {

    String NAME = "cuba_TestingService";

    String executeFor(int timeMillis);

    // Works in unit test mode only
    String executeUpdateSql(String sql);

    // Works in unit test mode only
    String executeSelectSql(String sql);

    String execute();

    boolean primitiveParameters(boolean b, int i, long l, double d);

    String executeWithException() throws TestException;

    /**
     * Warning! Removes all scheduled tasks from the database!
     */
    void clearScheduledTasks();

    @SupportedByClient
    @Logging(Logging.Type.BRIEF)
    public static class TestException extends Exception {

        public TestException(String message) {
            super(message);
        }
    }
}
