FROM tomcat:9.0
USER root

RUN  mkdir -p /usr/local/tomcat/conf \
    && chown -R 1001:root  /usr/local/tomcat/conf \
    && chmod -R a+rwx /usr/local/tomcat/conf \
    && chown -R 1001:root /usr/local/tomcat/webapps \
    && chmod -R a+rwx /usr/local/tomcat/webapps \
    && chmod -R 777 /tmp/

RUN echo 'JAVA_OPTS="$JAVA_OPTS -Dshutdown.cron=$SHUTDOWN_CRON -Dlotl.completed.markfile=$READY_MARKFILE -Dtsa.mock=$TSA_MOCK -Dtest.keystore.enabled=$KEYSTORE_ENABLED -Dcors.allowedorigins=$CORS_ALLOWED_ORIGINS -Dproxy.http.enabled=${PROXY_ENABLED:-true} -Dproxy.http.host=$PROXY_HOST -Dproxy.http.port=$PROXY_PORT -Dproxy.http.exclude=$PROXY_NONPROXYHOST -Dproxy.https.enabled=${PROXY_ENABLED:-true} -Dproxy.https.host=$PROXY_HOST -Dproxy.https.port=$PROXY_PORT -Dproxy.https.exclude=$PROXY_NONPROXYHOST -Dlogging.level.eu.europa.esig.dss.tsl.service=DEBUG -Djava.net.preferIPv4Stack=true -Dobjectstorage.endpoint=$S3ENDPOINT -Dobjectstorage.accesskey=$S3ACCESSKEY -Dobjectstorage.secretkey=$S3SECRETKEY -Dobjectstorage.secretbucket=$S3SECRETBUCKET -Dprofileconfig.jsonpath=/opt/signvalidation/profiles -Dprofileconfig.skip_dev_profiles=$IS_PROD -Dfonts.path=/opt/signvalidation/fonts"' > /usr/local/tomcat/bin/setenv.sh

ADD ./signandvalidation-ws/target/*.war /usr/local/tomcat/webapps/signandvalidation.war
ADD ./parameters /opt/signvalidation/profiles
ADD ./fonts /opt/signvalidation/fonts
COPY ./catalina_wrapper.sh /usr/local/tomcat/bin

USER root
COPY Certigna.crt $JAVA_HOME/lib/security
RUN cd $JAVA_HOME/lib/security \
    && keytool keytool --list -keystore cacerts -storepass changeit
RUN cd $JAVA_HOME/lib/security \
    && keytool keytool -import -alias certigna -file Certigna.crt -keystore cacerts -storepass changeit \
    && rm Certigna.crt

USER 1001
CMD bin/catalina_wrapper.sh run

