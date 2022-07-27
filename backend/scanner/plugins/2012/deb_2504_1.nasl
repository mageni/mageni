# OpenVAS Vulnerability Test
# $Id: deb_2504_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2504-1 (libspring-2.5-java)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71483");
  script_cve_id("CVE-2011-2730");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:07:37 -0400 (Fri, 10 Aug 2012)");
  script_name("Debian Security Advisory DSA 2504-1 (libspring-2.5-java)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202504-1");
  script_tag(name:"insight", value:"It was discovered that the Spring Framework contains an information
disclosure vulnerability in the processing of certain Expression
Language (EL) patterns, allowing attackers to access sensitive
information using HTTP requests.

NOTE: This update adds a springJspExpressionSupport context parameter
which must be manually set to false when the Spring Framework runs
under a container which provides EL support itself.

For the stable distribution (squeeze), this problem has been fixed in
version 2.5.6.SEC02-2+squeeze1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your libspring-2.5-java packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to libspring-2.5-java
announced via advisory DSA 2504-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libspring-aop-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-aspects-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-beans-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-context-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-context-support-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-core-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-jdbc-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-jms-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-orm-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-test-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-tx-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-web-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-webmvc-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-webmvc-portlet-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspring-webmvc-struts-2.5-java", ver:"2.5.6.SEC02-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}