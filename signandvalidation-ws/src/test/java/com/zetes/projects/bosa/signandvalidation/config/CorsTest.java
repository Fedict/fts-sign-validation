package com.zetes.projects.bosa.signandvalidation.config;

import com.zetes.projects.bosa.signandvalidation.SignAndValidationTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CorsTest extends SignAndValidationTestBase {

    @Test
    public void signingPingShouldReturnPong() {
        // when
        String result = this.restTemplate.getForObject(LOCALHOST + port + "/signing/ping", String.class);

        // then
        assertEquals("pong", result);
    }

    @Test
    void testCorsAllowed() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Origin", "abc");
        HttpEntity entityReq = new HttpEntity(headers);
        ResponseEntity<String> respEntity = restTemplate.exchange(LOCALHOST + port + "/signing/ping", HttpMethod.GET, entityReq, String.class);

        assertEquals("pong", respEntity.getBody());

        headers = new HttpHeaders();
        headers.set("Origin", "def");
        entityReq = new HttpEntity(headers);
        respEntity = restTemplate.exchange(LOCALHOST + port + "/signing/ping", HttpMethod.GET, entityReq, String.class);

        assertEquals("pong", respEntity.getBody());
    }

    @Test
    void testCorsNotAllowed() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Origin", "xyz");
        HttpEntity entityReq = new HttpEntity(headers);
        ResponseEntity<String> respEntity = restTemplate.exchange(LOCALHOST + port + "/signing/ping", HttpMethod.GET, entityReq, String.class);

        assertEquals("Invalid CORS request", respEntity.getBody());
    }

}
