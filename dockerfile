FROM tomcat:9.0
USER root

RUN chown -R 1001:root /usr/local/tomcat/webapps \
    && chmod -R a+rwx /usr/local/tomcat/webapps \
    && chmod -R 777 /tmp/

ADD ./signandvalidation-ws/target/*.war /usr/local/tomcat/webapps/signandvalidation.war    

USER 1001