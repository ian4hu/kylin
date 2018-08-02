package org.apache.kylin.rest.security.session;

import java.time.Instant;

import javax.servlet.http.Cookie;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.MapSession;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.ServletWebRequest;

import static org.junit.Assert.*;

public class CookieBasedSessionRepositoryTest {

    private static final String SESSION_KEY = "sess-key";

    @Test
    public void testSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MapSession session = new MapSession();
        session.setAttribute("attr", "value");
        session.setLastAccessedTime(Instant.now());
        MockHttpServletResponse response = new MockHttpServletResponse();
        CookieBasedSessionRepository repository = new CookieBasedSessionRepository(request, response, SESSION_KEY);
        repository.save(session);
        Cookie cookie = response.getCookie(SESSION_KEY);
        assertNotNull(cookie);
        assertNotNull(cookie.getValue());

        request.setCookies(cookie);
        MapSession result = repository.findById(session.getId());
        assertNotNull(result);
        assertEquals(session.getAttribute("attr"), result.getAttribute("attr"));
        assertEquals(session.getLastAccessedTime(), result.getLastAccessedTime());

        assertNull(repository.findById("not-exists"));
    }

}
