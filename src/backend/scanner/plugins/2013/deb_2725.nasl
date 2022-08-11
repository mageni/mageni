# OpenVAS Vulnerability Test
# $Id: deb_2725.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2725-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.892725");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2012-4534", "CVE-2012-3544", "CVE-2013-2067", "CVE-2012-5885", "CVE-2012-5887", "CVE-2012-4431", "CVE-2012-2733", "CVE-2012-5886", "CVE-2012-3546");
  script_name("Debian Security Advisory DSA 2725-1 (tomcat6 - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-07-18 00:00:00 +0200 (Thu, 18 Jul 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2725.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"tomcat6 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 6.0.35-1+squeeze3. This update also provides fixes for
CVE-2012-2733,
CVE-2012-3546,
CVE-2012-4431,
CVE-2012-4534,
CVE-2012-5885,
CVE-2012-5886 and
CVE-2012-5887
,
which were all fixed for stable already.

For the stable distribution (wheezy), these problems have been fixed in
version 6.0.35-6+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your tomcat6 packages.");
  script_tag(name:"summary", value:"Two security issues have been found in the Tomcat servlet and JSP engine:

CVE-2012-3544
The input filter for chunked transfer encodings could trigger high
resource consumption through malformed CRLF sequences, resulting in
denial of service.

CVE-2013-2067
The FormAuthenticator module was vulnerable to session fixation.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libservlet2.5-java", ver:"6.0.35-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet2.5-java-doc", ver:"6.0.35-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.35-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6", ver:"6.0.35-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.35-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-common", ver:"6.0.35-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-docs", ver:"6.0.35-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.35-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-user", ver:"6.0.35-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet2.4-java", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet2.5-java", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet2.5-java-doc", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-common", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-docs", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-extras", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-user", ver:"6.0.35-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}