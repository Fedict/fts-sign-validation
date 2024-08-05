package com.bosa.signandvalidation.config;

import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.DelegatingRequestMatcherHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain buildFilterChain(HttpSecurity http) throws Exception {

        // Below is a Snyk false positive report : REST is stateless AND we're not authenticated so CSRF does not make sense
        http.csrf(AbstractHttpConfigurer::disable);

        // javadoc uses frames
        final AntPathRequestMatcher javadocAntPathRequestMatcher = new AntPathRequestMatcher("/apidocs/**");
        final HeaderWriter hw = new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN);
        final DelegatingRequestMatcherHeaderWriter javadocHdrWriter = new DelegatingRequestMatcherHeaderWriter(javadocAntPathRequestMatcher, hw);
        http.headers(headers -> {
            // Since Firefox v115 does not apply its own rule of "CSP frame-ancestors overrides X-Frame-Options DENY" we remove the X-Frame-Options
            headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
                    .addHeaderWriter(javadocHdrWriter)
                    .addHeaderWriter(new StaticHeadersWriter("Server", "ESIG-DSS"))
                    // Force adding “strict-transport-security” to HTTP headers
                    .addHeaderWriter(new StaticHeadersWriter("Strict-Transport-Security", "max-age=31536000; includeSubDomains"));
        });

        LoggerFactory.getLogger(WebSecurityConfig.class).info("WebSecurityConfig configured");

        return http.build();
    }
}
