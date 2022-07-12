# OpenVAS Vulnerability Test
# $Id: deb_3530.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3530-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703530");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2013-4286", "CVE-2013-4322", "CVE-2013-4590", "CVE-2014-0033",
                  "CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0119",
                  "CVE-2014-0227", "CVE-2014-0230", "CVE-2014-7810", "CVE-2015-5174",
                  "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706",
                  "CVE-2016-0714", "CVE-2016-0763");
  script_name("Debian Security Advisory DSA 3530-1 (tomcat6 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-25 00:00:00 +0100 (Fri, 25 Mar 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3530.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"tomcat6 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 6.0.45+dfsg-1~deb7u1.

We recommend that you upgrade your tomcat6 packages.");
  script_tag(name:"summary", value:"Multiple security vulnerabilities have
been fixed in the Tomcat servlet and JSP engine, which may result on bypass of
security manager restrictions, information disclosure, denial of service or session
fixation.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libservlet2.4-java", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet2.5-java", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libservlet2.5-java-doc", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-common", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-docs", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-extras", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tomcat6-user", ver:"6.0.45+dfsg-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}