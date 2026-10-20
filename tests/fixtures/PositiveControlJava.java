/*
 * Positive control for the Java detectors. Scanned in the same invocation as
 * the corpus, every time: a rule file that fails to load produces an empty
 * result set, and a zero from a detector that does not work looks exactly
 * like a zero from a clean codebase. Never scored, and never compiled --
 * there is no javac here, which is stated rather than implied.
 */
package test.ssrefuse;

import java.io.InputStream;
import java.net.URL;

public class PositiveControlJava {
    public String controlOpenStream(String url) throws Exception {
        try (InputStream body = new URL(url).openStream()) {
            return new String(body.readAllBytes());
        }
    }
}
