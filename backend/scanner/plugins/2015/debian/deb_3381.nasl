# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3381-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.703381");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806",
                "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843",
                "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4871", "CVE-2015-4872",
                "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893",
                "CVE-2015-4903", "CVE-2015-4911");
  script_name("Debian Security Advisory DSA 3381-1 (openjdk-7 - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2015-10-27 00:00:00 +0100 (Tue, 27 Oct 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3381.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"openjdk-7 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 7u85-2.6.1-6~deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 7u85-2.6.1-5~deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 7u85-2.6.1-5.

We recommend that you upgrade your openjdk-7 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in OpenJDK, an implementation of the Oracle Java platform, resulting
in the execution of arbitrary code, breakouts of the Java sandbox, information
disclosure, or denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"icedtea-7-jre-cacao:amd64", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-cacao:i386", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:amd64", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:i386", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-dbg:amd64", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-dbg:i386", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-demo", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-doc", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jdk:amd64", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jdk:i386", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre:amd64", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre:i386", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:amd64", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:i386", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:amd64", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:i386", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-source", ver:"7u85-2.6.1-6~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:amd64", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:i386", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-dbg:amd64", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-dbg:i386", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-demo", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-doc", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jdk:amd64", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jdk:i386", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre:amd64", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre:i386", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:amd64", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:i386", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:amd64", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:i386", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-7-source", ver:"7u85-2.6.1-5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}