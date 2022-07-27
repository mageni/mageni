# OpenVAS Vulnerability Test
# $Id: ubuntu_862_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_862_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-862-1 (php5)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  libapache2-mod-php5             5.1.2-1ubuntu3.17
  php5-cgi                        5.1.2-1ubuntu3.17
  php5-cli                        5.1.2-1ubuntu3.17

Ubuntu 8.04 LTS:
  libapache2-mod-php5             5.2.4-2ubuntu5.9
  php5-cgi                        5.2.4-2ubuntu5.9
  php5-cli                        5.2.4-2ubuntu5.9

Ubuntu 8.10:
  libapache2-mod-php5             5.2.6-2ubuntu4.5
  php5-cgi                        5.2.6-2ubuntu4.5
  php5-cli                        5.2.6-2ubuntu4.5

Ubuntu 9.04:
  libapache2-mod-php5             5.2.6.dfsg.1-3ubuntu4.4
  php5-cgi                        5.2.6.dfsg.1-3ubuntu4.4
  php5-cli                        5.2.6.dfsg.1-3ubuntu4.4

Ubuntu 9.10:
  libapache2-mod-php5             5.2.10.dfsg.1-2ubuntu6.3
  php5-cgi                        5.2.10.dfsg.1-2ubuntu6.3
  php5-cli                        5.2.10.dfsg.1-2ubuntu6.3

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-862-1";

tag_insight = "Maksymilian Arciemowicz discovered that PHP did not properly validate
arguments to the dba_replace function. If a script passed untrusted input
to the dba_replace function, an attacker could truncate the database. This
issue only applied to Ubuntu 6.06 LTS, 8.04 LTS, and 8.10. (CVE-2008-7068)

It was discovered that PHP's php_openssl_apply_verification_policy
function did not correctly handle SSL certificates with zero bytes in the
Common Name. A remote attacker could exploit this to perform a man in the
middle attack. (CVE-2009-3291)

It was discovered that PHP did not properly handle certain malformed images
when being parsed by the Exif module. A remote attacker could exploit this
flaw and cause the PHP server to crash, resulting in a denial of service.
(CVE-2009-3292)

Grzegorz Stachowiak discovered that PHP did not properly enforce
restrictions in the tempnam function. An attacker could exploit this issue
to bypass safe_mode restrictions. (CVE-2009-3557)

Grzegorz Stachowiak discovered that PHP did not properly enforce
restrictions in the posix_mkfifo function. An attacker could exploit this
issue to bypass open_basedir restrictions. (CVE-2009-3558)

Bogdan Calin discovered that PHP did not limit the number of temporary
files created when handling multipart/form-data POST requests. A remote
attacker could exploit this flaw and cause the PHP server to consume all
available resources, resulting in a denial of service. (CVE-2009-4017)

ATTENTION: This update changes previous PHP behaviour by limiting the
number of files in a POST request to 50. This may be increased by adding a
max_file_uploads directive to php.ini.

It was discovered that PHP did not properly enforce restrictions in the
proc_open function. An attacker could exploit this issue to bypass
safe_mode_protected_env_vars restrictions and possibly execute arbitrary
code with application privileges. (CVE-2009-4018)";
tag_summary = "The remote host is missing an update to php5
announced via advisory USN-862-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305753");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-12-03 22:10:42 +0100 (Thu, 03 Dec 2009)");
 script_cve_id("CVE-2008-7068", "CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3557", "CVE-2009-3558", "CVE-2009-4017", "CVE-2009-4018");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Ubuntu USN-862-1 (php5)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-862-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mhash", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysqli", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.1.2-1ubuntu3.17", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mhash", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.2.4-2ubuntu5.9", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mhash", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.2.6-2ubuntu4.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mhash", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.2.6.dfsg.1-3ubuntu4.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mhash", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.2.10.dfsg.1-2ubuntu6.3", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
