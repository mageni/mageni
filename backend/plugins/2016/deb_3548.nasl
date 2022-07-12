# OpenVAS Vulnerability Test
# $Id: deb_3548.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3548-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703548");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-0005", "CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111",
                  "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115",
                  "CVE-2016-2118");
  script_name("Debian Security Advisory DSA 3548-1 (samba - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-04-13 00:00:00 +0200 (Wed, 13 Apr 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3548.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|7)");
  script_tag(name:"affected", value:"samba on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 2:3.6.6-6+deb7u9. The oldstable distribution
is not affected by CVE-2016-2113 and CVE-2016-2114
.

For the stable distribution (jessie), these problems have been fixed in
version 2:4.2.10+dfsg-0+deb8u1. The issues were addressed by upgrading
to the new upstream version 4.2.10, which includes additional changes
and bugfixes. The depending libraries ldb, talloc, tdb and tevent
required as well an update to new upstream versions for this update.

For the unstable distribution (sid), these problems have been fixed in
version 2:4.3.7+dfsg-1.

Please
for further details (in particular for new options and defaults).

We'd like to thank Andreas Schneider and Guenther Deschner (Red Hat),
Stefan Metzmacher and Ralph Boehme (SerNet) and Aurelien Aptel (SUSE)
for the massive backporting work required to support Samba 3.6 and Samba
4.2 and Andrew Bartlett (Catalyst), Jelmer Vernooij and Mathieu Parent
for their help in preparing updates of Samba and the underlying
infrastructure libraries.

We recommend that you upgrade your samba packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in Samba, a SMB/CIFS file, print, and login server for Unix. The Common
Vulnerabilities and Exposures project identifies the following issues:

CVE-2015-5370
Jouni Knuutinen from Synopsys discovered flaws in the Samba DCE-RPC
code which can lead to denial of service (crashes and high cpu
consumption) and man-in-the-middle attacks.

CVE-2016-2110
Stefan Metzmacher of SerNet and the Samba Team discovered that the
feature negotiation of NTLMSSP does not protect against downgrade
attacks.

CVE-2016-2111When Samba is configured as domain controller, it allows remote
attackers to spoof the computer name of a secure channel's endpoint,
and obtain sensitive session information. This flaw corresponds to
the same vulnerability as CVE-2015-0005
for Windows, discovered by
Alberto Solino from Core Security.

CVE-2016-2112
Stefan Metzmacher of SerNet and the Samba Team discovered that a
man-in-the-middle attacker can downgrade LDAP connections to avoid
integrity protection.

CVE-2016-2113
Stefan Metzmacher of SerNet and the Samba Team discovered that
man-in-the-middle attacks are possible for client triggered LDAP
connections and ncacn_http connections.

CVE-2016-2114
Stefan Metzmacher of SerNet and the Samba Team discovered that Samba
does not enforce required smb signing even if explicitly configured.

CVE-2016-2115
Stefan Metzmacher of SerNet and the Samba Team discovered that SMB
connections for IPC traffic are not integrity-protected.

CVE-2016-2118
Stefan Metzmacher of SerNet and the Samba Team discovered that a
man-in-the-middle attacker can intercept any DCERPC traffic between
a client and a server in order to impersonate the client and obtain
the same privileges as the authenticated user account.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");
  script_xref(name:"URL", value:"https://www.samba.org/samba/latest_news.html#4.4.2");
  script_xref(name:"URL", value:"https://www.samba.org/samba/history/samba-4.2.0.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/history/samba-4.2.10.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ctdb", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind:amd64", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind:i386", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-smbpass:amd64", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-smbpass:i386", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-winbind:amd64", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-winbind:i386", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libparse-pidl-perl", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient:amd64", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient:i386", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev:amd64", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev:i386", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient-dev:amd64", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient-dev:i386", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0:amd64", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0:i386", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-samba", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-libs:amd64", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-libs:i386", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"2:4.2.10+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind:amd64", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind:i386", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-smbpass:amd64", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-smbpass:i386", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-winbind:amd64", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-winbind:i386", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient:amd64", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient:i386", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev:amd64", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev:i386", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient-dev:amd64", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient-dev:i386", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libwbclient0:amd64", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0:i386", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"samba", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"swat", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"2:3.6.6-6+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}