###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4164.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4164-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704164");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1303", "CVE-2018-1312");
  script_name("Debian Security Advisory DSA 4164-1 (apache2 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-03 00:00:00 +0200 (Tue, 03 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4164.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB[89]");
  script_tag(name:"affected", value:"apache2 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 2.4.10-10+deb8u12.

For the stable distribution (stretch), these problems have been fixed in
version 2.4.25-3+deb9u4.

We recommend that you upgrade your apache2 packages.

For the detailed security status of apache2 please refer to its security
tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/apache2");
  script_tag(name:"summary", value:"Several vulnerabilities have been found in the Apache HTTPD server.

CVE-2017-15710
Alex Nichols and Jakob Hirsch reported that mod_authnz_ldap, if
configured with AuthLDAPCharsetConfig, could cause an of bound write
if supplied with a crafted Accept-Language header. This could
potentially be used for a Denial of Service attack.

CVE-2017-15715
Elar Lang discovered that expression specified in could
match '$' to a newline character in a malicious filename, rather
than matching only the end of the filename. This could be exploited
in environments where uploads of some files are are externally
blocked, but only by matching the trailing portion of the filename.

CVE-2018-1283When mod_session is configured to forward its session data to CGI
applications (SessionEnv on, not the default), a remote user could
influence their content by using a Session
header.

CVE-2018-1301
Robert Swiecki reported that a specially crafted request could have
crashed the Apache HTTP Server, due to an out of bound access after
a size limit is reached by reading the HTTP header.

CVE-2018-1303
Robert Swiecki reported that a specially crafted HTTP request header
could have crashed the Apache HTTP Server if using
mod_cache_socache, due to an out of bound read while preparing data
to be cached in shared memory.

CVE-2018-1312
Nicolas Daniels discovered that when generating an HTTP Digest
authentication challenge, the nonce sent by mod_auth_digest to
prevent reply attacks was not correctly generated using a
pseudo-random seed. In a cluster of servers using a common Digest
authentication configuration, HTTP requests could be replayed across
servers by an attacker without detection.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"apache2", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-data", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dev", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-ssl-dev", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-pristine", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.4.25-3+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-data", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dev", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-pristine", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-macro", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-proxy-html", ver:"2.4.10-10+deb8u12", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}