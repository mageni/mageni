# OpenVAS Vulnerability Test
# $Id: deb_3169.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3169-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703169");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406", "CVE-2013-7424",
                "CVE-2014-4043", "CVE-2014-9402", "CVE-2015-1472", "CVE-2015-1473");
  script_name("Debian Security Advisory DSA 3169-1 (eglibc - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-23 00:00:00 +0100 (Mon, 23 Feb 2015)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3169.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"eglibc on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these issues are fixed in version 2.13-38+deb7u8 of the eglibc package.

For the unstable distribution (sid), all the above issues are fixed in version
2.19-15 of the glibc package.

We recommend that you upgrade your eglibc packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been fixed
in eglibc, Debian's version of the GNU C library:

CVE-2012-3406The vfprintf function in stdio-common/vfprintf.c in GNU C Library (aka
glibc) 2.5, 2.12, and probably other versions does not properly restrict
the use of the alloca function when allocating the SPECS array, which
allows context-dependent attackers to bypass the FORTIFY_SOURCE
format-string protection mechanism and cause a denial of service (crash)
or possibly execute arbitrary code via a crafted format string using
positional parameters and a large number of format specifiers, a different
vulnerability than
CVE-2012-3404 and
CVE-2012-3405
.

CVE-2013-7424
An invalid free flaw was found in glibc's getaddrinfo() function when used
with the AI_IDN flag. A remote attacker able to make an application call
this function could use this flaw to execute arbitrary code with the
permissions of the user running the application. Note that this flaw only
affected applications using glibc compiled with libidn support.

CVE-2014-4043
The posix_spawn_file_actions_addopen function in glibc before 2.20 does not
copy its path argument in accordance with the POSIX specification, which
allows context-dependent attackers to trigger use-after-free
vulnerabilities.

CVE-2014-9402
The getnetbyname function in glibc 2.21 or earlier will enter an infinite
loop if the DNS backend is activated in the system Name Service Switch
configuration, and the DNS resolver receives a positive answer while
processing the network name.

CVE-2015-1472 /
CVE-2015-1473
Under certain conditions wscanf can allocate too little memory for the
to-be-scanned arguments and overflow the allocated buffer. The incorrect
use of '__libc_use_alloca (newsize)' caused a different (and weaker)
policy to be enforced which could allow a denial of service attack.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"eglibc-source", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"glibc-doc", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc-bin", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc-dev-bin", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-dbg", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-dev", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-dev-i386", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-i386", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-i686", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-pic", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-prof", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc0.1-udeb", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6:i386", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6:amd64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-amd64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dbg:amd64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dbg:i386", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev:amd64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev:i386", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libc6-dev-amd64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-i386", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-mips64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-mipsn32", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-ppc64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-s390", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-s390x", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-sparc64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-i386", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-i686", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-loongson2f", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-mips64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-mipsn32", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-pic", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-ppc64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-prof", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-s390", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-s390x", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-sparc64", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-udeb", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-xen", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-dbg", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-dev", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-pic", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-prof", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-udeb", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-dns-udeb", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-files-udeb", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"locales", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"locales-all", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multiarch-support", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nscd", ver:"2.13-38+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}