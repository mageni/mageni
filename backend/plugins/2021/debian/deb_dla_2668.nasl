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
  script_oid("1.3.6.1.4.1.25623.1.0.892668");
  script_version("2021-05-30T03:00:14+0000");
  script_cve_id("CVE-2019-10218", "CVE-2019-14833", "CVE-2019-14847", "CVE-2019-14861", "CVE-2019-14870", "CVE-2019-14902", "CVE-2019-14907", "CVE-2021-20254");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-06-01 10:36:35 +0000 (Tue, 01 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-30 03:00:14 +0000 (Sun, 30 May 2021)");
  script_name("Debian LTS: Security Advisory for samba (DLA-2668-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00023.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2668-1");
  script_xref(name:"Advisory-ID", value:"DLA-2668-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/946786");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the DLA-2668-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Samba, SMB/CIFS file,
print, and login server for Unix

CVE-2019-10218

A flaw was found in the samba client, where a malicious server can
supply a pathname to the client with separators. This could allow
the client to access files and folders outside of the SMB network
pathnames. An attacker could use this vulnerability to create
files outside of the current working directory using the
privileges of the client user.

CVE-2019-14833

A flaw was found in Samba, in the way it handles a user password
change or a new password for a samba user. The Samba Active
Directory Domain Controller can be configured to use a custom
script to check for password complexity. This configuration can
fail to verify password complexity when non-ASCII characters are
used in the password, which could lead to weak passwords being set
for samba users, making it vulnerable to dictionary attacks.

CVE-2019-14847

A flaw was found in samba where an attacker can crash AD DC LDAP
server via dirsync resulting in denial of service. Privilege
escalation is not possible with this issue.

CVE-2019-14861

Samba have an issue, where the (poorly named) dnsserver RPC pipe
provides administrative facilities to modify DNS records and
zones. Samba, when acting as an AD DC, stores DNS records in LDAP.
In AD, the default permissions on the DNS partition allow creation
of new records by authenticated users. This is used for example to
allow machines to self-register in DNS. If a DNS record was
created that case-insensitively matched the name of the zone, the
ldb_qsort() and dns_name_compare() routines could be confused into
reading memory prior to the list of DNS entries when responding to
DnssrvEnumRecords() or DnssrvEnumRecords2() and so following
invalid memory as a pointer.

CVE-2019-14870

Samba have an issue, where the S4U (MS-SFU) Kerberos delegation
model includes a feature allowing for a subset of clients to be
opted out of constrained delegation in any way, either S4U2Self or
regular Kerberos authentication, by forcing all tickets for these
clients to be non-forwardable. In AD this is implemented by a user
attribute delegation_not_allowed (aka not-delegated), which
translates to disallow-forwardable. However the Samba AD DC does
not do that for S4U2Self and does set the forwardable flag even if
the impersonated client has the not-delegated flag set.

CVE-2019-14902

There is an issue in samba, where the removal of the right to
create or modify a subtree would not automatically be taken away
on all domain controllers.

CVE-2019-14907

samba have an issue where if it is set  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2:4.5.16+dfsg-1+deb9u4.

We recommend that you upgrade your samba packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ctdb", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnss-winbind", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpam-winbind", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libparse-pidl-perl", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwbclient0", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-samba", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-libs", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"2:4.5.16+dfsg-1+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
