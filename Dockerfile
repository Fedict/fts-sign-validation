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

RUN cd $JAVA_HOME/lib/security && keytool --list -cacerts -storepass changeit | grep -q "FB:8F:EC:75:91:69:B9:10:6B:1E:51:16"

RUN cd $JAVA_HOME/lib/security && keytool --list -cacerts -storepass changeit | grep -q "Certificate fingerprint (SHA-256): 71:E6:53:BF:BF:5E:72:51:5B:40:99:BB:D5:EC:88:72:81:2B:47:C6:EC:1F:A9:AD:D3:27:E1:C9:2C:9E:A1:6D"

COPY Certigna.crt $JAVA_HOME/lib/security
RUN cd $JAVA_HOME/lib/security \
    && keytool -import -alias certigna -file Certigna.crt -cacerts -storepass changeit \
    && rm Certigna.crt

RUN cd $JAVA_HOME/lib/security && keytool --list -cacerts -storepass changeit | grep -q "Certificate fingerprint (SHA-256): 71:E6:53:BF:BF:5E:72:51:5B:40:99:BB:D5:EC:88:72:81:2B:47:C6:EC:1F:A9:AD:D3:27:E1:C9:2C:9E:A1:6D"

USER 1001
CMD bin/catalina_wrapper.sh run

