package com.zetes.projects.bosa.signandvalidation.controller;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.europa.esig.dss.diagnostic.jaxb.*;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("localh2")
class SignAndValidationTestBase {

    public static final String LOCALHOST = "http://localhost:";

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate restTemplate;

    @BeforeAll
    static void setupDeserializer(ApplicationContext applicationContext) {
        SimpleModule module = new SimpleModule();
        module.addDeserializer(XmlTimestampedObject.class, new XmlTimestampedObjectDeserializer());
        applicationContext.getBean(ObjectMapper.class).registerModule(module);
    }

    @Test
    void contextLoads() {
    }

    @Test
    void testCorsAllowed() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Origin", "abc");
        HttpEntity entityReq = new HttpEntity(headers);
        ResponseEntity<String> respEntity = restTemplate.exchange(LOCALHOST + port + "/signing/ping", HttpMethod.GET, entityReq, String.class);

        assertEquals("poooooong", respEntity.getBody());

        headers = new HttpHeaders();
        headers.set("Origin", "def");
        entityReq = new HttpEntity(headers);
        respEntity = restTemplate.exchange(LOCALHOST + port + "/signing/ping", HttpMethod.GET, entityReq, String.class);

        assertEquals("poooooong", respEntity.getBody());
    }

    @Test
    void testCorsNotAllowed() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Origin", "xyz");
        HttpEntity entityReq = new HttpEntity(headers);
        ResponseEntity<String> respEntity = restTemplate.exchange(LOCALHOST + port + "/signing/ping", HttpMethod.GET, entityReq, String.class);

        assertEquals("Invalid CORS request", respEntity.getBody());
    }

    private static class XmlTimestampedObjectDeserializer extends StdDeserializer<XmlTimestampedObject> {

        private static final long serialVersionUID = -5743323649165950906L;

        protected XmlTimestampedObjectDeserializer() {
            super(XmlTimestampedObject.class);
        }

        @Override
        public XmlTimestampedObject deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
            ObjectMapper mapper = (ObjectMapper) jp.getCodec();
            ObjectNode root = mapper.readTree(jp);
            JsonNode categoryNode = root.get("Category");
            TimestampedObjectType category = TimestampedObjectType.valueOf(categoryNode.textValue());
            JsonNode tokenNode = root.get("Token");

            XmlTimestampedObject timestampedObject = new XmlTimestampedObject();
            timestampedObject.setCategory(category);

            XmlAbstractToken token = null;
            switch (category) {
                case SIGNATURE:
                    token = new XmlSignature();
                    break;
                case CERTIFICATE:
                    token = new XmlCertificate();
                    break;
                case REVOCATION:
                    token = new XmlRevocation();
                    break;
                case TIMESTAMP:
                    token = new XmlTimestamp();
                    break;
                case SIGNED_DATA:
                    token = new XmlSignerData();
                    break;
                case ORPHAN:
                    token = new XmlOrphanToken();
                    break;
                default:
                    throw new InvalidFormatException(jp, "Unsupported category value " + category, category, TimestampedObjectType.class);
            }

            token.setId(tokenNode.textValue());
            timestampedObject.setToken(token);
            return timestampedObject;
        }

    }

}
