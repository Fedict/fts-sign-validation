FROM tomcat:9.0
USER root

RUN  mkdir -p /usr/local/tomcat/conf \
    && chown -R 1001:root  /usr/local/tomcat/conf \
    && chmod -R a+rwx /usr/local/tomcat/conf \
    && chown -R 1001:root /usr/local/tomcat/webapps \
    && chmod -R a+rwx /usr/local/tomcat/webapps \
    && chmod -R 777 /tmp/

RUN echo 'JAVA_OPTS="$JAVA_OPTS -Dresourcelocator.datasource.url=$RESOURCES_URL -Dresourcelocator.datasource.username=$RESOURCES_USER -Dresourcelocator.datasource.password=$RESOURCES_PW -Dresourcelocator.hibernate.default_schema=$RESOURCES_SCHEMA -Dsigningconfigurator.datasource.url=$SIGNING_URL -Dsigningconfigurator.datasource.username=$SIGNING_USER -Dsigningconfigurator.datasource.password=$SIGNING_PW -Dsigningconfigurator.hibernate.default_schema=$SIGNING_SCHEMA -Dcors.allowedorigins=$CORS_ALLOWED_ORIGINS -Dhttp.proxySet=true -Dhttp.proxyHost=$PROXY_HOST -Dhttp.proxyPort=$PROXY_PORT -Dhttps.proxyHost=$PROXY_HOST -Dhttps.proxyPort=$PROXY_PORT -Dhttp.nonProxyHosts=$PROXY_NONPROXYHOST -Dhttps.nonProxyHosts=$PROXY_NONPROXYHOST"' > /usr/local/tomcat/bin/setenv.sh

ADD ./signandvalidation-ws/target/*.war /usr/local/tomcat/webapps/signandvalidation.war

USER 1001