# OpenVAS Vulnerability Test
# $Id: deb_3280.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3280-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703280");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-2783", "CVE-2015-3329", "CVE-2015-4021", "CVE-2015-4022",
                  "CVE-2015-4024", "CVE-2015-4025", "CVE-2015-4026");
  script_name("Debian Security Advisory DSA 3280-1 (php5 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-07 00:00:00 +0200 (Sun, 07 Jun 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3280.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|9|8)");
  script_tag(name:"affected", value:"php5 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), these problems have been fixed
in version 5.4.41-0+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 5.6.9+dfsg-0+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 5.6.9+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 5.6.9+dfsg-1.

We recommend that you upgrade your php5 packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in PHP:

CVE-2015-4025 /
CVE-2015-4026
Multiple function didn't check for NULL bytes in path names.

CVE-2015-4024
Denial of service when processing multipart/form-data requests.

CVE-2015-4022
Integer overflow in the ftp_genlist() function may result in
denial of service or potentially the execution of arbitrary code.

CVE-2015-4021 CVE-2015-3329 CVE-2015-2783
Multiple vulnerabilities in the phar extension may result in
denial of service or potentially the execution of arbitrary code
when processing malformed archives.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-pear", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cli", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-common", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-curl", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dev", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gd", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-imap", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-intl", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-recode", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.4.41-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
# On the final stretch release this package has version 1.10.1+submodules+notgz-9 which causes a false positive
#if((res = isdpkgvuln(pkg:"php-pear", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
#    report += res;
#}
if((res = isdpkgvuln(pkg:"php5", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cli", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-common", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-curl", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dev", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gd", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-imap", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-intl", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-phpdbg", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-readline", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-recode", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.6.9+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-pear", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cli", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-common", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-curl", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dev", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gd", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-imap", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-intl", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-phpdbg", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-readline", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-recode", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.6.9+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}