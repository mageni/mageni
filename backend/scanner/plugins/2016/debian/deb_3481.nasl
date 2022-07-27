# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3481-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.703481");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8778", "CVE-2015-8779");
  script_name("Debian Security Advisory DSA 3481-1 (glibc - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-02-16 00:00:00 +0100 (Tue, 16 Feb 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3481.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"glibc on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 2.19-18+deb8u3.

For the unstable distribution (sid), these problems will be fixed in
version 2.21-8.

We recommend that you upgrade your glibc packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been fixed
in the GNU C Library, glibc.

The first vulnerability listed below is considered to have critical
impact.

CVE-2015-7547
The Google Security Team and Red Hat discovered that the glibc
host name resolver function, getaddrinfo, when processing
AF_UNSPEC queries (for dual A/AAAA lookups), could mismanage its
internal buffers, leading to a stack-based buffer overflow and
arbitrary code execution. This vulnerability affects most
applications which perform host name resolution using getaddrinfo,
including system services.

CVE-2015-8776
Adam Nielsen discovered that if an invalid separated time value
is passed to strftime, the strftime function could crash or leak
information. Applications normally pass only valid time
information to strftime. No affected applications are known.

CVE-2015-8778
Szabolcs Nagy reported that the rarely-used hcreate and hcreate_r
functions did not check the size argument properly, leading to a
crash (denial of service) for certain arguments. No impacted
applications are known at this time.

CVE-2015-8779
The catopen function contains several unbound stack allocations
(stack overflows), causing it the crash the process (denial of
service). No applications where this issue has a security impact
are currently known.

While it is only necessary to ensure that all processes are not using
the old glibc anymore, it is recommended to reboot the machines after
applying the security upgrade.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"glibc-doc", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"glibc-source", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc-bin", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc-dev-bin", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-amd64", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-amd64", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-i386", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-mips64", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-mipsn32", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-ppc64", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-s390", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-x32", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-i386", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-i686", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-loongson2f", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-mips64", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-mipsn32", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-pic", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-ppc64", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-s390", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-x32", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-xen", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"locales", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"locales-all", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multiarch-support", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nscd", ver:"2.19-18+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}