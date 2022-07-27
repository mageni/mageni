# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891891");
  script_version("2019-08-20T12:58:09+0000");
  script_cve_id("CVE-2019-13057", "CVE-2019-13565");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-20 12:58:09 +0000 (Tue, 20 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-20 02:00:14 +0000 (Tue, 20 Aug 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1891-1] openldap security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00024.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1891-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/932997");
  script_xref(name:"URL", value:"https://bugs.debian.org/932998");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap'
  package(s) announced via the DSA-1891-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were discovered in openldap, a server
and tools to provide a standalone directory service.

CVE-2019-13057

When the server administrator delegates rootDN (database admin)
privileges for certain databases but wants to maintain isolation
(e.g., for multi-tenant deployments), slapd does not properly stop a
rootDN from requesting authorization as an identity from another
database during a SASL bind or with a proxyAuthz (RFC 4370) control.
(It is not a common configuration to deploy a system where the
server administrator and a DB administrator enjoy different levels
of trust.)

CVE-2019-13565

When using SASL authentication and session encryption, and relying
on the SASL security layers in slapd access controls, it is possible
to obtain access that would otherwise be denied via a simple bind
for any identity covered in those ACLs. After the first SASL bind is
completed, the sasl_ssf value is retained for all new non-SASL
connections. Depending on the ACL configuration, this can affect
different types of operations (searches, modifications, etc.). In
other words, a successful authorization step completed by one user
affects the authorization requirement for a different user.");

  script_tag(name:"affected", value:"'openldap' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.4.40+dfsg-1+deb8u5.

We recommend that you upgrade your openldap packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ldap-utils", ver:"2.4.40+dfsg-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2", ver:"2.4.40+dfsg-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2-dbg", ver:"2.4.40+dfsg-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libldap2-dev", ver:"2.4.40+dfsg-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.40+dfsg-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slapd-dbg", ver:"2.4.40+dfsg-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slapd-smbk5pwd", ver:"2.4.40+dfsg-1+deb8u5", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);