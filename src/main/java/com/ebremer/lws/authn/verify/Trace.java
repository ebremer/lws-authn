/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.verify;

import java.util.UUID;

/**
 * Correlation ids for verification failures.
 *
 * <p>A verify endpoint is reachable by parties this deployment does not trust, so its responses must
 * not describe the server's own network — a resolved internal address, an upstream status code or a
 * raw exception message all tell an attacker what is behind this host. The detail therefore goes to
 * the server log and the client gets only this id, which an operator can grep for.</p>
 *
 * @author Erich Bremer
 */
public final class Trace {

    private Trace() {
    }

    /** A short, unique-enough id to correlate a client-visible failure with a log line. */
    public static String newId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
