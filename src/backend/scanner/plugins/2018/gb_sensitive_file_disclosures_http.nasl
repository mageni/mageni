##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sensitive_file_disclosures_http.nasl 12573 2018-11-29 09:52:12Z cfischer $
#
# Sensitive File Disclosure (HTTP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107305");
  script_version("2019-03-27T07:53:00+0000");
  script_tag(name:"last_modification", value:"2019-03-27 07:53:00 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-04-20 16:04:01 +0200 (Fri, 20 Apr 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_name("Sensitive File Disclosure (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "drupal_detect.nasl", "sw_magento_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify files containing sensitive data at the remote web server like e.g.:

  - software (Blog, CMS) configuration

  - database backup files

  - SSH or SSL/TLS Private-Keys");

  script_tag(name:"vuldetect", value:"Enumerate the remote web server and check if sensitive files are accessible.");

  script_tag(name:"impact", value:"Based on the information provided in this files an attacker might
  be able to gather additional info and/or sensitive data like usernames and passwords.");

  script_tag(name:"solution", value:"The sensitive files shouldn't be accessible via a web server.
  Restrict access to it or remove it completely.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(900);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

# nb: We can't save an array within an array so we're using:
# array index = the file to check
# array value = the description and the regex of the checked file separated with #-#. Optional a third entry separated by #-# containing an "extra_check" for http_vuln_check()
genericfiles = make_array(
"/.git-credentials", 'Git Credential Storage File containing a username and/or password.#-#^[ ]*https?://[^:@]+[:@]',
"/.idea/WebServers.xml", 'IntelliJ Platform Configuration File containing a username and/or password.#-#<component name="WebServers">#-#(password|username)=',
"/config/databases.yml", 'Symfony Framework Database Configuration File containing a username and/or password.#-#(param|class) ?:#-#(username|password) ?:',
"/config/database.yml", 'Rails Database Configuration File containing a username and/or password.#-#(adapter|database) ?:#-#(username|password) ?:',
"/DEADJOE", 'Editor JOE created the file DEADJOE on crash, which contains content of the currently edited files.#-#JOE (when it|was) aborted',
"/server.key", 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY',
"/privatekey.key", 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY',
"/myserver.key", 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY',
"/key.pem", 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY',
"/id_rsa", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/id_dsa", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (DSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/id_dss", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (DSS|ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/id_ecdsa", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/id_ed25519", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/.env", 'Laravel ".env" files present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_staging", 'Laravel ".env" files present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_local", 'Laravel ".env" files present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_production", 'Laravel ".env" files present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_hosted", 'Laravel ".env" files present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_baremetal", 'Laravel ".env" files present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/app/config/parameters.yml", 'Contao CMS or PrestaShop Database Configuration File containing a username and/or password.#-#parameters ?:#-#database_(user|password) ?:',
"/config.development.json", 'Ghost Database Configuration File containing a username and/or password.#-#"database" ?:#-#"(user|password)"',
"/config.production.json", 'Ghost Database Configuration File containing a username and/or password.#-#"database" ?:#-#"(user|password)"',
# https://docs.djangoproject.com/en/2.0/ref/settings/
"/settings.py", "Django Configuration File containing a SECRET_KEY or a username and/or password.#-#(SECRET_KEY ?=|'USER' ?:|'PASSWORD' ?:)",
# https://blog.dewhurstsecurity.com/2018/06/07/database-sql-backup-files-alexa-top-1-million.html
# https://github.com/hannob/snallygaster/blob/a423d4063f37763f9288505c0baca69e216daa7c/snallygaster#L352-L355
"/dump.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/database.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/1.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/backup.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/data.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/db_backup.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/dbdump.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/db.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/localhost.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/mysql.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/site.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/sql.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/temp.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/users.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/translate.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/mysqldump.sql", 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
# e.g.
# {"php":"7.2.4-1+ubuntu16.04.1+deb.sury.org+1","version":"2.11.1:v2.11.1#ad94441c17b8ef096e517acccdbf3238af8a2da8","rules":{"binary_operator_spaces":true,"blank_line_after_opening_tag":true,"blank_line_before_statement":{"statements":
# {"php":"5.6.26-1+deb.sury.org~xenial+1","version":"2.0.0","rules":{"array_syntax":{"syntax":"short"},"combine_consecutive_unsets":true,"general_phpdoc_annotation_remove":
"/.php_cs.cache", 'Cache file .php_cs.cache of PHP-CS-Fixer could expose a listing of PHP files.#-#^{"php":"#-#"(version|rules|binary_operator_spaces|blank_line_after_opening_tag|blank_line_before_statement|array_syntax|syntax|statements)":"'
);

# https://doc.nette.org/en/configuring or https://github.com/nette/examples/blob/master/CD-collection/app/config.neon
foreach nettedir( make_list( "/app/config", "/app", "" ) ) {
  genericfiles[nettedir + "/config.neon"] = "Nette Framework config file is publicly accessible.#-#^(php:|application:|database:|services:|security:|# SECURITY WARNING: it is CRITICAL|latte:|session:|extensions:)#-#^ *(date.timezone:|mapping:|dsn:|- App\Model\|debugger:|users:|roles:|resources:|errorPresenter:|catchExceptions:|silentLinks:|user:|password:|macros:)";
}

# Add domain specific key names and backup files from above
hnlist = create_hostname_parts_list();
foreach hn( hnlist ) {
  genericfiles["/" + hn + ".key"] = 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY';
  genericfiles["/" + hn + ".pem"] = 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY';
  genericfiles["/" + hn + ".sql"] = 'Database backup file publicly accessible.#-#^(-- MySQL dump |INSERT INTO |DROP TABLE |CREATE TABLE )';
}

magentofiles = make_array(
"/app/etc/local.xml", 'Magento 1 Database Configuration File containing a username and/or password.#-#(<config|Mage)#-#<(username|password)>' );

drupalfiles = make_array(
"/sites/default/private/files/backup_migrate/scheduled/test.txt", 'If the file "test.txt" is accessible on a Drupal server, it means that site backups may be publicly exposed.#-#this file should not be publicly accessible',
"/sites/default/files/.ht.sqlite", "Drupal Database file publicly accessible.#-#^SQLite format [0-9]" );

global_var report, VULN;

function check_files( filesarray, dirlist, port ) {

  local_var filesarray, dirlist, port, dir, file, infos, extra, url;

  foreach dir( dirlist ) {

    if( dir == "/" ) dir = "";

    foreach file( keys( filesarray ) ) {

      # infos[0] contains the description, infos[1]  the regex. Optionally infos[2] contains an extra_check for http_vuln_check
      infos = split( filesarray[file], sep:"#-#", keep:FALSE );
      if( max_index( infos ) < 2 ) continue; # Something is wrong with the provided info...

      if( max_index( infos ) > 2 )
        extra = make_list( infos[2] );
      else
        extra = NULL;

      url = dir + file;

      if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:infos[1], extra_check:extra, usecache:TRUE ) ) {
        report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE ) + ":" + infos[0];
        VULN = TRUE;
      }
    }
  }
}

report = 'The following files containing sensitive information were identified (URL:Description):\n';

port = get_http_port( default:80 );

dirlist = make_list_unique( "/", cgi_dirs( port:port ) );
check_files( filesarray:genericfiles, dirlist:dirlist, port:port );

drdirs = get_app_location( port:port, cpe:"cpe:/a:drupal:drupal", nofork:TRUE );
if( drdirs )
  drupaldirlist = make_list_unique( drdirs, dirlist );
else
  drupaldirlist = dirlist;
check_files( filesarray:drupalfiles, dirlist:drupaldirlist, port:port );

madirs = get_app_location( port:port, cpe:"cpe:/a:magentocommerce:magento", nofork:TRUE );
if( madirs )
  magentodirlist = make_list_unique( madirs, dirlist );
else
  magentodirlist = dirlist;
check_files( filesarray:magentofiles, dirlist:magentodirlist, port:port );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
