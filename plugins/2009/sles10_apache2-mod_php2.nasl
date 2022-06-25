#
#VID slesp2-apache2-mod_php5-5345
# OpenVAS Vulnerability Test
# $
# Description: Security update for PHP5
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    apache2-mod_php5
    php5
    php5-bcmath
    php5-bz2
    php5-calendar
    php5-ctype
    php5-curl
    php5-dba
    php5-dbase
    php5-devel
    php5-dom
    php5-exif
    php5-fastcgi
    php5-ftp
    php5-gd
    php5-gettext
    php5-gmp
    php5-iconv
    php5-imap
    php5-json
    php5-ldap
    php5-mbstring
    php5-mcrypt
    php5-mhash
    php5-mysql
    php5-ncurses
    php5-odbc
    php5-openssl
    php5-pcntl
    php5-pdo
    php5-pear
    php5-pgsql
    php5-posix
    php5-pspell
    php5-shmop
    php5-snmp
    php5-soap
    php5-sockets
    php5-sqlite
    php5-suhosin
    php5-sysvmsg
    php5-sysvsem
    php5-sysvshm
    php5-tokenizer
    php5-wddx
    php5-xmlreader
    php5-xmlrpc
    php5-xsl
    php5-zlib


More details may also be found by searching for the SuSE
Enterprise Server 10 patch database located at
http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309979");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
 script_cve_id("CVE-2008-0599");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("SLES10: Security update for PHP5");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-json", rpm:"php5-json~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.2.5~9.6", rls:"SLES10.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
