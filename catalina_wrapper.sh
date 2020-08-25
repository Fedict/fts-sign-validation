#!/bin/bash

declare -a ARGS=("$@")

i=0

while [ ! -z "${ARGS[$i]}" ]; do
	if [ "${ARGS[$i]}" = "run" ]; then
		ARGS[$i]="start"
	fi
	i=$(( $i + 1 ))
done

/usr/local/tomcat/bin/catalina.sh "${ARGS[@]}"
tail -F /usr/local/tomcat/logs/catalina.out
