#!/bin/bash

# Nagios plugin to collect certificate expiry from a keystore
# Reworked by fulopm with keystore password, and fixed handling of certificate chains 
# Official source by jooperik: https://gist.github.com/jooperik/b97ddcddfc237ec2d7b7358eb97f3b1c


KEYTOOL="/usr/lib/jvm/java-11-amazon-corretto/bin/keytool"
THRESHOLD_IN_DAYS=8
KEYSTORE=""
PASSWORD=""
VIEW_ALL=0
RETURN_CODE=0
OK_CERTS=0
WARNING_CERTS=0
CRITICAL_CERTS=0

ARGS=`getopt -o k:p:t:a -l keystore:,password:,threshold:,all -n "$0" -- "$@"`

function usage {
	echo "Usage: $0 -k|--keystore <keystore> -p|--password <password> [-t|--threshold <threshold>] [-a|--all]"
	exit
}

function start {
	CURRENT=`date +%s`

	THRESHOLD=$(($CURRENT + ($THRESHOLD_IN_DAYS*24*60*60)))
	if [ $THRESHOLD -le $CURRENT ]; then
        echo "[ERROR] Invalid date."
        exit 1
	fi

	CERTS="$(echo | $KEYTOOL -list -v -keystore "$KEYSTORE" 2>&1 | grep Alias | awk '{print $3}')"

	while read ALIAS
	do
		# Iterate through all the certificate alias
		SERIAL_NO_HEX="$(echo | $KEYTOOL -list -v -keystore "$KEYSTORE" -storepass "$PASSWORD" -alias $ALIAS 2>&1 | grep 'Serial number:' | cut -d' ' -f3 | head -n 1)"
		SERIAL_NO=$((16#${SERIAL_NO_HEX}))
		UNTIL="$(echo | $KEYTOOL -list -v -keystore "$KEYSTORE" -storepass "$PASSWORD" -alias $ALIAS 2>&1 | grep Valid | head -n 1 | perl -ne 'if(/until: (.*?)\n/) { print "$1\n"; }')"
		UNTIL_SECONDS=`date -d "$UNTIL" +%s`
		REMAINING_DAYS=$(( ($UNTIL_SECONDS -  $(date +%s)) / 60 / 60 / 24 ))
		if [ $THRESHOLD -le $UNTIL_SECONDS ]; then
			((OK_CERTS++))
			if [ $VIEW_ALL -eq 1 ]; then echo "[OK] Certificate '$ALIAS' (SN: $SERIAL_NO_HEX) expires in '$UNTIL' ($REMAINING_DAYS day(s) remaining)."; fi
		elif [ $REMAINING_DAYS -le 0 ]; then
            ((CRITICAL_CERTS++))
			if [ $VIEW_ALL -eq 1 ]; then echo "[CRITICAL] Certificate $ALIAS (SN: $SERIAL_NO_HEX) has already expired."; fi
			RETURN_CODE=2
		else
			((WARNING_CERTS++))
			if [ $VIEW_ALL -eq 1 ]; then echo "[WARNING] Certificate '$ALIAS' (SN: $SERIAL_NO_HEX)  expires in '$UNTIL' ($REMAINING_DAYS day(s) remaining)."; fi
			RETURN_CODE=1
        	fi
	done <<< "$CERTS"

	case "${RETURN_CODE}" in
	0)
		echo "status OK: ok:$OK_CERTS warning:$WARNING_CERTS critical:$CRITICAL_CERTS"
		;;
	1)
		echo "STATUS WARNING: ok:$OK_CERTS warning:$WARNING_CERTS critical:$CRITICAL_CERTS"
		;;
	*)
		echo "STATUS CRITICAL: ok:$OK_CERTS warning:$WARNING_CERTS critical:$CRITICAL_CERTS"
		;;
	esac
	exit $RETURN_CODE
}

eval set -- "$ARGS"

while true
do
	case "$1" in
		-k|--keystore)
			if [ ! -f "$2" ]; then echo "Keystore not found: $1"; exit 1; else KEYSTORE=$2; fi
			shift 2;;
		-t|--threshold)
			if [ -n "$2" ] && [[ $2 =~ ^[0-9]+$ ]]; then THRESHOLD_IN_DAYS=$2; else echo "Invalid threshold"; exit 1; fi
			shift 2;;
		-a|--all)
			VIEW_ALL=1
			shift;;
		-p|--password)
			if [ -n "$2" ]; then PASSWORD=$2; else echo "Invalid password"; exit 1; fi
			shift 2;;
		--)
			shift;
			break;;
	esac
done

if [ -n "$KEYSTORE" ] && [ -n "$PASSWORD" ]; then
	start
else
	usage
	fi
