package org.apache.kylin.rest.security.session;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.compress.utils.IOUtils;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.Session;
import org.springframework.util.Base64Utils;
import org.springframework.web.util.WebUtils;

public class CookieBasedSessionRepository extends MapSessionRepository {

    private final HttpServletResponse response;

    private final HttpServletRequest request;

    private final String sessionKey;

    public CookieBasedSessionRepository(HttpServletRequest request, HttpServletResponse response, String sessionKey) {
        super(new HashMap<String, Session>());
        this.response = response;
        this.request = request;
        this.sessionKey = sessionKey;
    }

    @Override
    public void save(MapSession session) {
        super.save(session);
        Cookie cookie = new Cookie(sessionKey, encode(session));
        cookie.setPath(request.getContextPath());
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    @Override
    public MapSession findById(String id) {
        MapSession mapSession = super.findById(id);
        if (mapSession != null) {
            return mapSession;
        }
        Cookie cookie = WebUtils.getCookie(request, sessionKey);
        if (cookie == null) {
            return null;
        }
        String value = cookie.getValue();
        MapSession session = decode(value);
        if (session == null || !Objects.equals(id, session.getId())) {
            return null;
        }
        super.save(session);
        return session;
    }

    private static String encode(MapSession session) {
        byte[] content = serialize(session);
        byte[] sha = Sha512DigestUtils.sha(content);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(sha.length);
        try {
            out.write(sha);
            try (GZIPOutputStream zout = new GZIPOutputStream(out)) {
                zout.write(content);
                zout.flush();
            }
        } catch (IOException e) {
            // ignored
        }
        return Base64Utils.encodeToUrlSafeString(out.toByteArray());
    }

    private static MapSession decode(String cookieValue) {
        byte[] bytes = Base64Utils.decodeFromUrlSafeString(cookieValue);
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);
        int len = in.read();
        if (len < 0) {
            return null;
        }
        byte[] sha = new byte[len];
        if (in.read(sha, 0, len) != len) {
            return null;
        }
        try (GZIPInputStream zin = new GZIPInputStream(in)) {
            byte[] content = IOUtils.toByteArray(zin);
            byte[] sha1 = Sha512DigestUtils.sha(content);
            if (!Arrays.equals(sha, sha1)) {
                return null;
            }
            return deserialize(content);
        } catch (IOException e) {
            return null;
        }
    }

    private static byte[] serialize(MapSession session) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(session);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static MapSession deserialize(byte[] bytes) {
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);
        try (ObjectInputStream stream = new ObjectInputStream(in)) {
            return (MapSession) stream.readObject();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
