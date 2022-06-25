# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892328");
  script_version("2020-08-17T13:22:26+0000");
  script_cve_id("CVE-2020-12100", "CVE-2020-12673", "CVE-2020-12674");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-18 10:12:19 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-17 13:22:26 +0000 (Mon, 17 Aug 2020)");
  script_name("Debian LTS: Security Advisory for dovecot (DLA-2328-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00024.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2328-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/968302");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot'
  package(s) announced via the DLA-2328-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Dovecot email
server.

CVE-2020-12100

Receiving mail with deeply nested MIME parts leads to resource
exhaustion as Dovecot attempts to parse it.

CVE-2020-12673

Dovecot's NTLM implementation does not correctly check message
buffer size, which leads to a crash when reading past allocation.

CVE-2020-12674

Dovecot's RPA mechanism implementation accepts zero-length message,
which leads to assert-crash later on.");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:2.2.27-3+deb9u6.

We recommend that you upgrade your dovecot packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-dbg", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.2.27-3+deb9u6", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
