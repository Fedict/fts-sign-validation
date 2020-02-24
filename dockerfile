FROM tomcat:9.0
ADD ./signandvalidation-ws/target/*.war /usr/local/tomcat/webapps/signandvalidation.war    