# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.705205");
  script_version("2022-08-15T10:11:29+0000");
  script_cve_id("CVE-2022-2031", "CVE-2022-32742", "CVE-2022-32744", "CVE-2022-32745", "CVE-2022-32746");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-15 10:11:29 +0000 (Mon, 15 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-13 01:00:16 +0000 (Sat, 13 Aug 2022)");
  script_name("Debian: Security Advisory for samba (DSA-5205-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5205.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5205-1");
  script_xref(name:"Advisory-ID", value:"DSA-5205-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the DSA-5205-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Samba, a SMB/CIFS file,
print, and login server for Unix.

CVE-2022-2031
Luke Howard reported that Samba AD users can bypass certain
restrictions associated with changing passwords. A user who has been
requested to change their password can exploit this to obtain and
use tickets to other services.

CVE-2022-32742
Luca Moro reported that a SMB1 client with write access to a share
can cause server memory content to be leaked.

CVE-2022-32744
Joseph Sutton reported that Samba AD users can forge password change
requests for any user, resulting in privilege escalation.

CVE-2022-32745
Joseph Sutton reported that Samba AD users can crash the server
process with a specially crafted LDAP add or modify request.

CVE-2022-32746
Joseph Sutton and Andrew Bartlett reported that Samba AD users can
cause a use-after-free in the server process with a specially
crafted LDAP add or modify request.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 2:4.13.13+dfsg-1~deb11u5. The fix for
CVE-2022-32745

required an update to ldb 2:2.2.3-2~deb11u2 to correct the defect.

We recommend that you upgrade your samba packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ctdb", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnss-winbind", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpam-winbind", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwbclient0", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-samba", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-libs", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"2:4.13.13+dfsg-1~deb11u5", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
