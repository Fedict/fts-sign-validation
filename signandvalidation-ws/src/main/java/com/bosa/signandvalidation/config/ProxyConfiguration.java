package com.bosa.signandvalidation.config;

import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collection;

@Configuration
public class ProxyConfiguration {

    @Value("${proxy.http.enabled}")
    private boolean httpEnabled;
    @Value("${proxy.http.host}")
    private String httpHost;
    @Value("${proxy.http.port}")
    private int httpPort;
    @Value("${proxy.http.user}")
    private String httpUser;
    @Value("${proxy.http.password}")
    private String httpPassword;
    @Value("#{'${proxy.http.exclude}'.split(',')}")
    private Collection<String> httpExcludedHosts;

    @Value("${proxy.https.enabled}")
    private boolean httpsEnabled;
    @Value("${proxy.https.host}")
    private String httpsHost;
    @Value("${proxy.https.port}")
    private int httpsPort;
    @Value("${proxy.https.user}")
    private String httpsUser;
    @Value("${proxy.https.password}")
    private String httpsPassword;
    @Value("#{'${proxy.https.exclude}'.split(',')}")
    private Collection<String> httpsExcludedHosts;

    @Bean
    public ProxyConfig proxyConfig() {
        if (!httpEnabled && !httpsEnabled) {
            return null;
        }
        ProxyConfig config = new ProxyConfig();
        if (httpEnabled) {
            ProxyProperties httpProperties = new ProxyProperties();
            httpProperties.setHost(httpHost);
            httpProperties.setPort(httpPort);
            httpProperties.setUser(httpUser);
            httpProperties.setPassword(httpPassword.toCharArray());
            httpProperties.setExcludedHosts(httpExcludedHosts);
            config.setHttpProperties(httpProperties);
        }
        if (httpsEnabled) {
            ProxyProperties httpsProperties = new ProxyProperties();
            httpsProperties.setHost(httpsHost);
            httpsProperties.setPort(httpsPort);
            httpsProperties.setUser(httpsUser);
            httpsProperties.setPassword(httpsPassword.toCharArray());
            httpsProperties.setExcludedHosts(httpsExcludedHosts);
            config.setHttpsProperties(httpsProperties);
        }
        return config;
    }

}
