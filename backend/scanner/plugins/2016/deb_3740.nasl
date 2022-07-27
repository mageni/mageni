# OpenVAS Vulnerability Test
# $Id: deb_3740.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3740-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703740");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-2119", "CVE-2016-2123", "CVE-2016-2125", "CVE-2016-2126");
  script_name("Debian Security Advisory DSA 3740-1 (samba - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-12-19 00:00:00 +0100 (Mon, 19 Dec 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3740.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"samba on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 2:4.2.14+dfsg-0+deb8u2. In addition, this
update contains several changes originally targeted for the upcoming jessie point
release.

We recommend that you upgrade your samba packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in Samba, a SMB/CIFS file, print, and login server for Unix. The Common
Vulnerabilities and Exposures project identifies the following issues:

CVE-2016-2119
Stefan Metzmacher discovered that client-side SMB2/3 required
signing can be downgraded, allowing a man-in-the-middle attacker to
impersonate a server being connected to by Samba, and return
malicious results.

CVE-2016-2123
Trend Micro's Zero Day Initiative and Frederic Besler discovered
that the routine ndr_pull_dnsp_name, used to parse data from the
Samba Active Directory ldb database, contains an integer overflow
flaw, leading to an attacker-controlled memory overwrite. An
authenticated user can take advantage of this flaw for remote
privilege escalation.

CVE-2016-2125
Simo Sorce of Red Hat discovered that the Samba client code always
requests a forwardable ticket when using Kerberos authentication. A
target server, which must be in the current or trusted domain/realm,
is given a valid general purpose Kerberos Ticket Granting Ticket

(TGT), which can be used to fully impersonate the authenticated user
or service.

CVE-2016-2126
Volker Lendecke discovered several flaws in the Kerberos PAC
validation. A remote, authenticated, attacker can cause the winbindd
process to crash using a legitimate Kerberos ticket due to incorrect
handling of the PAC checksum. A local service with access to the
winbindd privileged pipe can cause winbindd to cache elevated access
permissions.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ctdb", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-smbpass:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-smbpass:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-winbind:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-winbind:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libparse-pidl-perl", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbclient-dev:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbsharemodes-dev:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbsharemodes-dev:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbsharemodes0:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbsharemodes0:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient-dev:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient-dev:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient0:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"python-samba", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-libs:amd64", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-libs:i386", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"smbclient", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"2:4.2.14+dfsg-0+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}