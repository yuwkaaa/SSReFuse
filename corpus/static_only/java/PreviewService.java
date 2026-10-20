/*
 * Static-only corpus: Java.
 *
 * Nothing here runs in the testbed. There is no Java lab, so these methods
 * have no dynamic ground truth and they must never enter the precision and
 * recall table: a label nobody reproduced is a claim about a file, and this
 * project scores detectors against labels the prober confirmed.
 *
 * What they are for is the other half of the question -- "which sinks does a
 * rule see" -- which does not need the code to run. Every outbound-request
 * sink is marked with @ssrefuse:sink so the evaluator can say how many of the
 * sinks that are there were found, and name the ones that were not.
 *
 * There is no javac on the build machine, so these files are checked by the
 * scanner and not by a compiler. That is stated rather than hidden: a file
 * that does not compile can still be the thing a pattern fails to match, but
 * it cannot be claimed to be valid Java.
 */
package test.ssrefuse;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class PreviewService {

    private static final String ALLOWED_HOST = "public.ssrefuse.test";

    /** The sink the brief names: URLConnection, with no validation at all. */
    public String previewDirect(String url) throws Exception {
        URL target = new URL(url);
        // @ssrefuse:sink java-urlconnection
        URLConnection connection = target.openConnection();
        connection.setConnectTimeout(4000);
        try (InputStream body = connection.getInputStream()) {
            return new String(body.readAllBytes());
        }
    }

    /** The one-call form, which is the same sink without the intermediate. */
    public String previewOpenStream(String url) throws Exception {
        // @ssrefuse:sink java-url-openstream
        try (InputStream body = new URL(url).openStream()) {
            return new String(body.readAllBytes());
        }
    }

    /** HttpURLConnection, which follows redirects unless told not to. */
    public int previewHead(String url) throws Exception {
        // @ssrefuse:sink java-httpurlconnection
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod("HEAD");
        connection.setInstanceFollowRedirects(true);
        return connection.getResponseCode();
    }

    /** The modern client. */
    public String previewHttpClient(String url) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).GET().build();
        // @ssrefuse:sink java-httpclient-send
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    /**
     * Two handlers the JVM ships that no other runtime in this corpus has.
     * `netdoc:` reads a local file, and `jar:` fetches a URL and then opens
     * it as an archive, which makes it a blind fetch primitive. A scheme
     * allowlist written as "not file:" misses both. Nothing here is
     * confirmed by a request -- there is no Java lab -- so this method
     * exists for the rules to meet, and the markers only count sinks.
     */
    public String previewJvmSchemes(String url) throws Exception {
        // @ssrefuse:sink java-netdoc-openstream
        try (InputStream local = new URL("netdoc:///etc/hostname").openStream()) {
            local.readAllBytes();
        }
        // @ssrefuse:sink java-jar-openstream
        try (InputStream archive = new URL("jar:" + url + "!/").openStream()) {
            return new String(archive.readAllBytes());
        }
    }

    /**
     * A hostname allowlist applied after parsing: the correct shape, and the
     * wrong effect for the same reason as everywhere else -- URI returns the
     * authority as written. This method is the false-positive counterpart for
     * the Java rules.
     */
    public String previewAllowlisted(String url) throws Exception {
        URI parsed = URI.create(url);
        if (!ALLOWED_HOST.equalsIgnoreCase(parsed.getHost())) {
            return "";
        }
        // @ssrefuse:sink java-urlconnection-guarded
        try (InputStream body = parsed.toURL().openStream()) {
            return new String(body.readAllBytes());
        }
    }
}
