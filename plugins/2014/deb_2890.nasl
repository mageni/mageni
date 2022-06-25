# OpenVAS Vulnerability Test
# $Id: deb_2890.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2890-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.702890");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-0054", "CVE-2014-1904");
  script_name("Debian Security Advisory DSA 2890-1 (libspring-java - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-03-29 00:00:00 +0100 (Sat, 29 Mar 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2890.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"libspring-java on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 3.0.6.RELEASE-6+deb7u3.

For the testing distribution (jessie) and the unstable distribution
(sid), these problems have been fixed in version 3.0.6.RELEASE-13.

We recommend that you upgrade your libspring-java packages.");
  script_tag(name:"summary", value:"Two vulnerabilities were discovered in libspring-java, the Debian
package for the Java Spring framework.

CVE-2014-0054
Jaxb2RootElementHttpMessageConverter in Spring MVC processes
external XML entities.

CVE-2014-1904
Spring MVC introduces a cross-site scripting vulnerability if the
action on a Spring form is not specified.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libspring-aop-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-beans-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-context-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-context-support-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-core-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-expression-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-instrument-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-jdbc-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-jms-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-orm-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-oxm-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-test-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-transaction-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-web-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-web-portlet-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-web-servlet-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-web-struts-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}