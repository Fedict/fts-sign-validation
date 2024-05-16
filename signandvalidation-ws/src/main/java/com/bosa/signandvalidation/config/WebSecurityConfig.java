package com.bosa.signandvalidation.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.DelegatingRequestMatcherHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${frame-ancestors}")
    private String frameAncestors;

    private static final Logger LOG = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // Below is a Snyk false positive report : REST is stateless AND we're not authenticated so CSRF does not make sense
        http.csrf().disable();

        // javadoc uses frames
        final AntPathRequestMatcher javadocAntPathRequestMatcher = new AntPathRequestMatcher("/apidocs/**");
        final HeaderWriter hw = new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN);
        final DelegatingRequestMatcherHeaderWriter javadocHdrWriter = new DelegatingRequestMatcherHeaderWriter(javadocAntPathRequestMatcher, hw);
        http.headers().addHeaderWriter(javadocHdrWriter);

        // so does the GUI thing, from a different domain even.
        http.headers().xssProtection().and().contentSecurityPolicy("frame-ancestors " + frameAncestors);
        // Since Firefox v115 does not apply its own rule of "CSP frame-ancestors overrides X-Frame-Options DENY" we remove the X-Frame-Options
        http.headers().frameOptions().disable();

        http.headers().addHeaderWriter(new StaticHeadersWriter("Server", "ESIG-DSS"));

        // Force adding “strict-transport-security” to HTTP headers
        http.headers().httpStrictTransportSecurity().requestMatcher(AnyRequestMatcher.INSTANCE);

        LOG.info("WebSecurityConfig configured");
    }
}
