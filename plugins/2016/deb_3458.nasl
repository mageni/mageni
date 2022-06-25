# OpenVAS Vulnerability Test
# $Id: deb_3458.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3458-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703458");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-7575", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466",
                  "CVE-2016-0483", "CVE-2016-0494");
  script_name("Debian Security Advisory DSA 3458-1 (openjdk-7 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-27 00:00:00 +0100 (Wed, 27 Jan 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3458.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|7)");
  script_tag(name:"affected", value:"openjdk-7 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 7u95-2.6.4-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 7u95-2.6.4-1~deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 7u95-2.6.4-1.

We recommend that you upgrade your openjdk-7 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in OpenJDK, an implementation of the Oracle Java platform, resulting
in breakouts of the Java sandbox, information disclosur, denial of service and
insecure cryptography.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:amd64", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:i386", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-dbg:amd64", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-dbg:i386", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-demo", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-doc", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jdk:amd64", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jdk:i386", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre:amd64", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre:i386", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:amd64", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:i386", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:amd64", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:i386", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-source", ver:"7u95-2.6.4-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-cacao:amd64", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-cacao:i386", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:amd64", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:i386", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-dbg:amd64", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-dbg:i386", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-demo", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-doc", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jdk:amd64", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jdk:i386", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre:amd64", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre:i386", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:amd64", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:i386", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:amd64", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:i386", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-source", ver:"7u95-2.6.4-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}