#!/bin/bash

#-Metadata----------------------------------------------------#
#  Filename: Sudomy - Subdomain Enumeration & Analysis        #
#-Author(s)---------------------------------------------------#
#  Edo maland ~ @screetsec                                    #
#  @mr-pmillz                                                 #
#-Info--------------------------------------------------------#
#  This file is part of Sudomy project                        #
#  Plugin Screenshots: Update = 2022-06-11                    #
#	- aquatone					      #
#-Licence-----------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT           #
#-------------------------------------------------------------#

function exec_aquatone(){
rm -rf ${OUT}/${DATE_LOG}/${DOMAIN}/screenshots/aquatone/* ## Cleaning old file
		echo -e "\n${BOLD}[${LGREEN}+${RESET}${BOLD}]${RESET} Web Screenshots: from domain list"
		echo -e "---------------------------------------------\n"
		## Check Folder Results
		[[ ! -e "${OUT}/${DATE_LOG}/${DOMAIN}/screenshots/aquatone" ]] && mkdir -p "${OUT}/${DATE_LOG}/${DOMAIN}/screenshots/aquatone" || true
		cat ${OUT}/${DATE_LOG}/${DOMAIN}/${RESULT_HTTPROBE} | ${_AQUATONE} -ports 80,443 -out ${OUT}/${DATE_LOG}/${DOMAIN}/screenshots/aquatone -screenshot-timeout 40000
}
