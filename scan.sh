#!/bin/sh
CURRENTDATE=$(date)
ARCHIVEDIR=$(pwd)"/archives-image/"
ARCHIVEDIRTAR=$(pwd)"/archives-image-tar/"
FINDINGSFILE=$(pwd)"/findings.txt"

echo "NOTE: Be aware to search as root for more results due to file system restrictions (e.g. chmod -R 777 $ARCHIVEDIR*)." 
echo "----------------------------------------------------------------------NEXT $ARCHIVEDIR"  >> $FINDINGSFILE
echo "----------------------------------------------------------------------NEXT REPO $REPO_NAME"  >> $FINDINGSFILE
echo "---------------------------------------------------------------------- SHADOW"  >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname shadow); do if grep -q '\$' $file; then echo $(realpath $file); grep '\$' $file; fi; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- SSH KEY" >> $FINDINGSFILE
find $ARCHIVEDIR -iname *id_[rd]sa >> $FINDINGSFILE
echo "---------------------------------------------------------------------- GIT CONFIG" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .git); do echo $file; cat $file/config; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- HTPASSWD" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .htpasswd); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- NPMRC" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .npmrc); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- DOCKERCFG" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .dockercfg); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- PPK" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname *.ppk); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- .CREDENTIALS" >> $FINDINGSFILE
#for file in $(find $ARCHIVEDIR -iname *.sql); do echo $file; cat $file; done >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .credentials); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- CREDENTIALS (AWS)" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname credentials); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- .S3CFG" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .s3cfg); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- WP-CONFIG.PHP" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname wp-config.php); do echo $file; cat $file; done >> $FINDINGSFILE
#echo "---------------------------------------------------------------------- *CONFIG.PHP" >> $FINDINGSFILE
#for file in $(find $ARCHIVEDIR -iname *config.php); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- .ENV" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .env); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- .GIT-CREDENTIALS" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .git-credentials); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- .BASH_HISTORY" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .bash_history); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- .NETRC" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .netrc); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- FILEZILLA.XML" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname filezilla.xml); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- RECENTSERVERS.XML" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname recentservers.xml); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- CONFIG.JSON" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname config.json); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- .PGPASS" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .pgpass); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- VENTRILO_SRV.INI" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname ventrilo_srv.ini); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- DBEAVER-DATA-SOURCES.XML" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname dbeaver-data-sources.xml); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- .ESMTPRC" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .esmtprc); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- LOGINS.JSON" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname logins.json); do echo $file; cat $file; done >> $FINDINGSFILE
#for file in $(find $ARCHIVEDIR -iname secrets.yml); do echo $file; cat $file; done >> $FINDINGSFILE
#for file in $(find $ARCHIVEDIR -iname secrets.yaml); do echo $file; cat $file; done >> $FINDINGSFILE
#for file in $(find $ARCHIVEDIR -iname settings.py); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- .FTPCONFIG" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname .ftpconfig); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- SFTP-CONFIG.JSON" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname sftp-config.json); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- TOKEN" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname token -type f); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- GALAXY TOKEN (ANSIBLE)" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname galaxy_token -type f); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- DATABASE.INI" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname database.ini -type f); do echo $file; cat $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- LDAP.CONF" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname ldap.conf -type f); do echo $file; cat $file |grep -v "^#"|sort -u; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- JWT/Kubernetes TOKEN" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname *.yaml -iname *.yml -type f); do  echo  $file; grep -i eyJhbGciOiJSUzI1 $file; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- SOPS" >> $FINDINGSFILE
for directory in $(find $ARCHIVEDIR -iname .sops -type d); do echo $directory; ls -lah $directory; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- KUBERNETES" >> $FINDINGSFILE
for directory in $(find $ARCHIVEDIR -iname .kube -type d); do echo $directory; ls -lah $directory; cat $directory/config*; done >> $FINDINGSFILE
echo "---------------------------------------------------------------------- docker-compose.yml" >> $FINDINGSFILE
for file in $(find $ARCHIVEDIR -iname docker-compose.yml -type f); do echo $file; echo $file; cat $file|grep -iE "(password|user|key.*=.*|login|account|url.*:.*@.*)"; done >> $FINDINGSFILE
#echo "---------------------------------------------------------------------- passwords/github" >> $FINDINGSFILE

#grep -lirs 'password' $ARCHIVEDIR >> $FINDINGSFILE
#grep -lirs 'passwort' $ARCHIVEDIR  >> $FINDINGSFILE
#grep -lirs 'github.com' $ARCHIVEDIR >> $FINDINGSFILE


echo "---------------------------------------------------------------------- DONE" >> $FINDINGSFILE


# Artifactory tokens begin with AKC
#e.compile(r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}(?:\s|"|$)'),  # API token
# Artifactory encrypted passwords begin with AP[A-Z]
# re.compile(r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|"|$)'),  # Password

#Trivy


#cd $ARCHIVEDIRTAR
#for tarfile in $(ls *.tar); do echo $tarfile; /home/a113017152/docker-image-scanner/tools/trivy/trivy image --offline-scan --scanners secret --output report-$tarfile.report  --input $tarfile; done
#for i in $(ls report*); do echo $i; echo "--------------------------------------------------------"; cat $i; done > ../trivy-reports-$CURRENTDATE
#echo "[*] Trivy reports are in: $(pwd ../trivy-reports-$CURRENTDATE)/trivy-reports$CURRENTDATE"
#echo "[*] Findings are in $FINDINGSFILE"
