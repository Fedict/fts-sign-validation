package com.bosa.signandvalidation.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

public class LoggingInterceptor implements ClientHttpRequestInterceptor {

    private static final Logger log = LoggerFactory.getLogger(LoggingInterceptor.class);
    private final AtomicInteger requestNumberSequence = new AtomicInteger(0);

    public static void logHttpRequest(RestTemplate restTemplate) {
        if (log.isInfoEnabled()) restTemplate.getInterceptors().add(new LoggingInterceptor());
    }

    @NotNull
    @Override
    public ClientHttpResponse intercept(@NotNull HttpRequest request, @NotNull byte[] body, ClientHttpRequestExecution execution) throws IOException {
        int requestNumber = requestNumberSequence.incrementAndGet();
        logRequest(requestNumber, request, body);
        ClientHttpResponse response = execution.execute(request, body);
        response = new BufferedClientHttpResponse(response);
        logResponse(requestNumber, response);
        return response;
    }

    private void logRequest(int requestNumber, HttpRequest request, byte[] body) throws JsonProcessingException {
        String prefix = requestNumber + " +++++++++++++++++ ";
        log.info("{} Request: {} {}", prefix, request.getMethod(), request.getURI());
        log.info("{} Headers: {}", prefix, request.getHeaders());
        if (body.length > 0) {
            String bodyStr = new String(body, StandardCharsets.UTF_8);
            if (bodyStr.charAt(0) == '{') {
                ObjectMapper om = new ObjectMapper();
                bodyStr = om.writerWithDefaultPrettyPrinter().writeValueAsString(om.readValue(bodyStr, Object.class));
            }
            log.info("{} Body: \n{}", prefix, bodyStr);
        }
    }

    private void logResponse(int requestNumber, ClientHttpResponse response) throws IOException {
        String prefix = requestNumber + "----------------- ";
        log.info("{} Response: {} {}", prefix, response.getStatusCode(), response.getStatusText());
        log.info("{} Headers: {}", prefix, response.getHeaders());
        String body = StreamUtils.copyToString(response.getBody(), StandardCharsets.UTF_8);
        if (!body.isEmpty()) {
            if (body.charAt(0) == '{') {
                ObjectMapper om = new ObjectMapper();
                body = om.writerWithDefaultPrettyPrinter().writeValueAsString(om.readValue(body, Object.class));
            }
            log.info("{} Body: \n{}", prefix, body);
        }
    }

    /**
     * Wrapper around ClientHttpResponse, buffers the body so it can be read repeatedly (for logging & consuming the result).
     */
    private static class BufferedClientHttpResponse implements ClientHttpResponse {

        private byte[] body;
        private final ClientHttpResponse response;

        public BufferedClientHttpResponse(ClientHttpResponse response) { this.response = response; }
        @NotNull @Override
        public HttpStatusCode getStatusCode() throws IOException { return response.getStatusCode(); }

        @NotNull @Override
        public String getStatusText() throws IOException { return response.getStatusText(); }

        @Override
        public void close() { response.close(); }

        @NotNull @Override
        public InputStream getBody() throws IOException {
            if (body == null) body = StreamUtils.copyToByteArray(response.getBody());
            return new ByteArrayInputStream(body);
        }

        @NotNull @Override
        public HttpHeaders getHeaders() { return response.getHeaders(); }
    }
}
