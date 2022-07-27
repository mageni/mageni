# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705003");
  script_version("2021-11-14T02:00:40+0000");
  script_cve_id("CVE-2016-2124", "CVE-2020-25717", "CVE-2020-25718", "CVE-2020-25719", "CVE-2020-25721", "CVE-2020-25722", "CVE-2021-23192", "CVE-2021-3738");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-14 02:00:40 +0000 (Sun, 14 Nov 2021)");
  script_name("Debian: Security Advisory for samba (DSA-5003-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5003.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5003-1");
  script_xref(name:"Advisory-ID", value:"DSA-5003-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the DSA-5003-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Samba, a SMB/CIFS file,
print, and login server for Unix.

CVE-2016-2124
Stefan Metzmacher reported that SMB1 client connections can be
downgraded to plaintext authentication.

CVE-2020-25717Andrew Bartlett reported that Samba may map domain users to local
users in an undesired way, allowing for privilege escalation. The
update introduces a new parameter min domain uid
(default to 1000)
to not accept a UNIX uid below this value.

CVE-2020-25718
Andrew Bartlett reported that Samba as AD DC, when joined by an
RODC, did not confirm if the RODC was allowed to print a ticket for
that user, allowing an RODC to print administrator tickets.

CVE-2020-25719
Andrew Bartlett reported that Samba as AD DC, did not always rely on
the SID and PAC in Kerberos tickets and could be confused about the
user a ticket represents. If a privileged account was attacked this
could lead to total domain compromise.

CVE-2020-25721
Andrew Bartlett reported that Samba as a AD DC did not provide a way
for Linux applications to obtain a reliable SID (and samAccountName)
in issued tickets.

CVE-2020-25722
Andrew Bartlett reported that Samba as AD DC did not do sufficient
access and conformance checking of data stored, potentially allowing
total domain compromise.

CVE-2021-3738
William Ross reported that the Samba AD DC RPC server can use memory
that was free'd when a sub-connection is closed, resulting in denial
of service, and potentially, escalation of privileges.

CVE-2021-23192
Stefan Metzmacher reported that if a client to a Samba server sent a
very large DCE/RPC request, and chose to fragment it, an attacker
could replace later fragments with their own data, bypassing the
signature requirements.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 2:4.13.13+dfsg-1~deb11u2.

We recommend that you upgrade your samba packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ctdb", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnss-winbind", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpam-winbind", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwbclient0", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-samba", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-libs", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"2:4.13.13+dfsg-1~deb11u2", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
