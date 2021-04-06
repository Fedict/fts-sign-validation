package com.zetes.projects.bosa.signandvalidation.config;

import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.DelegatingRequestMatcherHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.frameoptions.WhiteListedAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${cors.allowedorigins")
    private String allowedOrigins;

    private static final Logger LOG = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();

        // javadoc uses frames
        http.headers().addHeaderWriter(javadocHeaderWriter());
        // so does the GUI thing, from a different domain even.
        http.antMatcher("/signing/getDocumentForToken").headers().frameOptions().disable();
        http.headers().addHeaderWriter(serverEsigDSS());
        LOG.info("WebSecurityConfig configured");
    }

    @Bean
    public HeaderWriter javadocHeaderWriter() {
        final AntPathRequestMatcher javadocAntPathRequestMatcher = new AntPathRequestMatcher("/apidocs/**");
        final HeaderWriter hw = new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN);
        return new DelegatingRequestMatcherHeaderWriter(javadocAntPathRequestMatcher, hw);
    }

    public HeaderWriter serverEsigDSS() {
        return new StaticHeadersWriter("Server", "ESIG-DSS");
    }
}
