# OpenVAS Vulnerability Test
# $Id: deb_3433.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3433-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703433");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-2535", "CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296",
                  "CVE-2015-5299", "CVE-2015-5330", "CVE-2015-7540", "CVE-2015-8467");
  script_name("Debian Security Advisory DSA 3433-1 (samba - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-06 15:29:32 +0530 (Fri, 06 May 2016)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3433.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"samba on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 2:3.6.6-6+deb7u6. The oldstable distribution
(wheezy) is only affected by CVE-2015-5252, CVE-2015-5296 and CVE-2015-5299
.

For the stable distribution (jessie), these problems have been fixed in
version 2:4.1.17+dfsg-2+deb8u1. The fixes for CVE-2015-3223 and
CVE-2015-5330
required an update to ldb 2:1.1.17-2+deb8u1 to correct the
defects.

For the unstable distribution (sid), these problems have been fixed in
version 2:4.1.22+dfsg-1. The fixes for CVE-2015-3223 and CVE-2015-5330

required an update to ldb 2:1.1.24-1 to correct the defects.

We recommend that you upgrade your samba packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in Samba, a SMB/CIFS file, print, and login server for Unix. The Common
Vulnerabilities and Exposures project identifies the following issues:

CVE-2015-3223
Thilo Uttendorfer of Linux Information Systems AG discovered that a
malicious request can cause the Samba LDAP server to hang, spinning
using CPU. A remote attacker can take advantage of this flaw to
mount a denial of service.

CVE-2015-5252Jan Yenya
Kasprzak and the Computer Systems Unit team at Faculty
of Informatics, Masaryk University discovered that insufficient
symlink verification could allow data access outside an exported
share path.

CVE-2015-5296
Stefan Metzmacher of SerNet discovered that Samba does not ensure
that signing is negotiated when creating an encrypted client
connection to a server. This allows a man-in-the-middle attacker to
downgrade the connection and connect using the supplied credentials
as an unsigned, unencrypted connection.

CVE-2015-5299
It was discovered that a missing access control check in the VFS
shadow_copy2 module could allow unauthorized users to access
snapshots.

CVE-2015-5330
Douglas Bagnall of Catalyst discovered that the Samba LDAP server
is vulnerable to a remote memory read attack. A remote attacker can
obtain sensitive information from daemon heap memory by sending
crafted packets and then either read an error message, or a
database value.

CVE-2015-7540
It was discovered that a malicious client can send packets that
cause the LDAP server provided by the AD DC in the samba daemon
process to consume unlimited memory and be terminated.

CVE-2015-8467Andrew Bartlett of the Samba Team and Catalyst discovered that a
Samba server deployed as an AD DC can expose Windows DCs in the same
domain to a denial of service via the creation of multiple machine
accounts. This issue is related to the MS15-096 / CVE-2015-2535

security issue in Windows.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libnss-winbind:amd64", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind:i386", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-smbpass:amd64", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-smbpass:i386", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-winbind:amd64", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-winbind:i386", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbclient:amd64", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbclient:i386", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbclient-dev:amd64", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbclient-dev:i386", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient-dev:amd64", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient-dev:i386", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient0:amd64", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient0:i386", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"samba", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"swat", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"2:3.6.6-6+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libnss-winbind:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-smbpass:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-smbpass:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-winbind:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libpam-winbind:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libparse-pidl-perl", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbclient-dev:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbclient-dev:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbsharemodes-dev:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbsharemodes-dev:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbsharemodes0:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libsmbsharemodes0:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient-dev:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient-dev:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient0:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"python-samba", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-libs:amd64", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-libs:i386", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"2:4.1.17+dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}