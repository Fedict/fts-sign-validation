FROM tomcat:9.0
USER root

RUN  mkdir -p /usr/local/tomcat/conf \
    && chown -R 1001:root  /usr/local/tomcat/conf \
    && chmod -R a+rwx /usr/local/tomcat/conf \
    && chown -R 1001:root /usr/local/tomcat/webapps \
    && chmod -R a+rwx /usr/local/tomcat/webapps \
    && chmod -R 777 /tmp/ 

RUN (echo 'JAVA_OPTS="$JAVA_OPTS -Dlotl.completed.markfile=$READY_MARKFILE -Dtsa.mock=$TSA_MOCK -Dtest.keystore.enabled=$KEYSTORE_ENABLED -Dsigningconfigurator.datasource.url=$SIGNING_URL -Dsigningconfigurator.datasource.username=$SIGNING_USER -Dsigningconfigurator.datasource.password=$SIGNING_PW -Dsigningconfigurator.hibernate.default_schema=$SIGNING_SCHEMA -Dcors.allowedorigins=$CORS_ALLOWED_ORIGINS -Dproxy.http.enabled=${PROXY_ENABLE:-true} -Dproxy.http.host=$PROXY_HOST -Dproxy.http.port=$PROXY_PORT -Dproxy.http.exclude=$PROXY_NONPROXYHOST -Dproxy.https.enabled=${PROXY_ENABLE:-true} -Dproxy.https.host=$PROXY_HOST -Dproxy.https.port=$PROXY_PORT -Dproxy.https.exclude=$PROXY_NONPROXYHOST -Dlogging.level.eu.europa.esig.dss.tsl.service=DEBUG -Djava.net.preferIPv4Stack=true"'; > /usr/local/tomcat/bin/setenv.sh

ADD ./signandvalidation-ws/target/*.war /usr/local/tomcat/webapps/signandvalidation.war
COPY ./catalina_wrapper.sh /usr/local/tomcat/bin

USER 1001
CMD bin/catalina_wrapper.sh run
