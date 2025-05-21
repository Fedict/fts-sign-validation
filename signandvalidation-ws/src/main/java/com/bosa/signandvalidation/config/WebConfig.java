package com.bosa.signandvalidation.config;

import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.module.jakarta.xmlbind.JakartaXmlBindAnnotationIntrospector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private static final Logger LOG = LoggerFactory.getLogger(WebConfig.class);

    @Autowired
    private ThreadDataCleaner customRequestInterceptor;


    @Value("${cors.allowedorigins}")
    private String allowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        LOG.info("Adding CORS allowed origins: {}", allowedOrigins);
        CorsRegistration reg = registry.addMapping("/**")
                .allowedOriginPatterns(allowedOrigins.split(","))
                .allowCredentials(true);
    }

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();

        // JAXB is needed for DSS marshalling, we need to use Jackson annotations also
        // so we use a dual AnnotationIntrospector
        JakartaXmlBindAnnotationIntrospector primary = new JakartaXmlBindAnnotationIntrospector(TypeFactory.defaultInstance());
        JacksonAnnotationIntrospector secondary = new JacksonAnnotationIntrospector();
        objectMapper.setAnnotationIntrospector(AnnotationIntrospector.pair(primary, secondary));
        objectMapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        return objectMapper;
    }

    // Intercept every incoming request to clear the "exception log" maintained to identify error sources properly
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
         registry.addInterceptor(customRequestInterceptor);
    }
}
