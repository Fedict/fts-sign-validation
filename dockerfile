FROM tomcat:9.0

RUN echo 'JAVA_OPTS="$JAVA_OPTS -Dresourcelocator.datasource.url=$RESOURCES_URL -Dresourcelocator.datasource.username=$RESOURCES_USER -Dresourcelocator.datasource.password=$RESOURCES_PW -Dsigningconfigurator.datasource.url=$SIGNING_URL -Dsigningconfigurator.datasource.username=$SIGNING_USER -Dsigningconfigurator.datasource.password=$SIGNING_PW -Dcors.allowedorigins=$CORS_ALLOWED_ORIGINS"' > /usr/local/tomcat/bin/setenv.sh

ADD ./signandvalidation-ws/target/*.war /usr/local/tomcat/webapps/signandvalidation.war
