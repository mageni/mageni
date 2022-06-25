# OpenVAS Vulnerability Test
# $Id: deb_3380.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3380-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703380");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-7803", "CVE-2015-7804");
  script_name("Debian Security Advisory DSA 3380-1 (php5 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-10-27 00:00:00 +0100 (Tue, 27 Oct 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3380.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|9|8)");
  script_tag(name:"affected", value:"php5 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 5.4.45-0+deb7u2.

For the stable distribution (jessie), these problems have been fixed in
version 5.6.14+dfsg-0+deb8u1.

For the testing distribution (stretch) and the unstable distribution
(sid), these problems have been fixed in version 5.6.14+dfsg-1.

We recommend that you upgrade your php5 packages.");
  script_tag(name:"summary", value:"Two vulnerabilities were found in PHP,
a general-purpose scripting language commonly used for web application development.

CVE-2015-7803
The phar extension could crash with a NULL pointer dereference
when processing tar archives containing links referring to
non-existing files. This could lead to a denial of service.

CVE-2015-7804
The phar extension does not correctly process directory entries
found in archive files with the name '/', leading to a denial of
service and, potentially, information disclosure.

The update for Debian stable (jessie) contains additional bug fixes
from PHP upstream version 5.6.14.

Note to users of the oldstable distribution (wheezy): PHP 5.4 has
reached end-of-life on September 14th, 2015. As a result, there will
be no more new upstream releases. The security support of PHP 5.4 in
Debian oldstable (wheezy) will be best effort only, and you are
strongly advised to upgrade to latest Debian stable release (jessie),
which includes PHP 5.6.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-pear", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cli", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-common", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-curl", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dev", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gd", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-imap", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-intl", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-recode", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.4.45-0+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
# On the final stretch release this package has version 1.10.1+submodules+notgz-9 which causes a false positive
#if((res = isdpkgvuln(pkg:"php-pear", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
#    report += res;
#}
if((res = isdpkgvuln(pkg:"php5", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cli", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-common", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-curl", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dev", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gd", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-imap", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-intl", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-phpdbg", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-readline", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-recode", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.6.14+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-pear", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-cli", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-common", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-curl", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-dev", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gd", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-imap", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-intl", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-phpdbg", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-readline", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-recode", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.6.14+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}