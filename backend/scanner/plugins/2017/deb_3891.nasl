# OpenVAS Vulnerability Test
# $Id: deb_3891.nasl 14280 2019-03-18 14:50:45Z cfischer $
# Auto-generated from advisory DSA 3891-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703891");
  script_version("$Revision: 14280 $");
  script_cve_id("CVE-2017-5664");
  script_name("Debian Security Advisory DSA 3891-1 (tomcat8 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:50:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-06-22 00:00:00 +0200 (Thu, 22 Jun 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3891.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|10|8)");
  script_tag(name:"affected", value:"tomcat8 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has been fixed
in version 8.0.14-1+deb8u10.

For the stable distribution (stretch), this problem has been fixed in
version 8.5.14-1+deb9u1.

For the testing distribution (buster), this problem has been fixed
in version 8.5.14-2.

For the unstable distribution (sid), this problem has been fixed in
version 8.5.14-2.

We recommend that you upgrade your tomcat8 packages.");
  script_tag(name:"summary", value:"Aniket Nandkishor Kulkarni discovered that in tomcat8, a servlet and
JSP engine, static error pages used the original request's HTTP method
to serve content, instead of systematically using the GET method. This
could under certain conditions result in undesirable results,
including the replacement or removal of the custom error page.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libservlet3.1-java", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet3.1-java-doc", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtomcat8-embed-java", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-admin", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-common", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-docs", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-examples", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-user", ver:"8.5.14-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet3.1-java", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet3.1-java-doc", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtomcat8-embed-java", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-admin", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-common", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-docs", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-examples", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-user", ver:"8.5.14-2", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet3.1-java", ver:"8.0.14-1+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet3.1-java-doc", ver:"8.0.14-1+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.0.14-1+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8", ver:"8.0.14-1+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-admin", ver:"8.0.14-1+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-common", ver:"8.0.14-1+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-docs", ver:"8.0.14-1+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-examples", ver:"8.0.14-1+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat8-user", ver:"8.0.14-1+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}