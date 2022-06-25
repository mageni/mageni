# OpenVAS Vulnerability Test
# $Id: deb_3142.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3142-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703142");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2012-6656", "CVE-2014-6040", "CVE-2014-7817", "CVE-2015-0235");
  script_name("Debian Security Advisory DSA 3142-1 (eglibc - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-01-27 00:00:00 +0100 (Tue, 27 Jan 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3142.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"eglibc on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 2.13-38+deb7u7.

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), the
CVE-2015-0235

issue has been fixed in version 2.18-1 of the glibc package.

We recommend that you upgrade your eglibc packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
fixed in eglibc, Debian's version of the GNU C library:

CVE-2015-0235
Qualys discovered that the gethostbyname and gethostbyname2
functions were subject to a buffer overflow if provided with a
crafted IP address argument. This could be used by an attacker to
execute arbitrary code in processes which called the affected
functions.

The original glibc bug was reported by Peter Klotz.

CVE-2014-7817
Tim Waugh of Red Hat discovered that the WRDE_NOCMD option of the
wordexp function did not suppress command execution in all cases.
This allows a context-dependent attacker to execute shell
commands.

CVE-2012-6656 CVE-2014-6040
The charset conversion code for certain IBM multi-byte code pages
could perform an out-of-bounds array access, causing the process
to crash. In some scenarios, this allows a remote attacker to
cause a persistent denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"eglibc-source", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"glibc-doc", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc-bin", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc-dev-bin", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-dbg", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-dev", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-dev-i386", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-i386", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-i686", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-pic", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-prof", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-udeb", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-amd64", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-amd64", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-i386", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-mips64", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-mipsn32", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-ppc64", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-s390", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-s390x", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-sparc64", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-i386", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-i686", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-loongson2f", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-mips64", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-mipsn32", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-pic", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-ppc64", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-prof", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-s390", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-s390x", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-sparc64", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-udeb", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-xen", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-dbg", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-dev", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-pic", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-prof", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-udeb", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-dns-udeb", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-files-udeb", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"locales", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"locales-all", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multiarch-support", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nscd", ver:"2.13-38+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}