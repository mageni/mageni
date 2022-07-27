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
  script_oid("1.3.6.1.4.1.25623.1.0.892931");
  script_version("2022-03-07T02:00:09+0000");
  script_cve_id("CVE-2022-24407");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-07 11:11:30 +0000 (Mon, 07 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-07 02:00:09 +0000 (Mon, 07 Mar 2022)");
  script_name("Debian LTS: Security Advisory for cyrus-sasl2 (DLA-2931-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/03/msg00002.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2931-1");
  script_xref(name:"Advisory-ID", value:"DLA-2931-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-sasl2'
  package(s) announced via the DLA-2931-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the SQL plugin in cyrus-sasl2, a library
implementing the Simple Authentication and Security Layer, is prone to a
SQL injection attack. An authenticated remote attacker can take advantage
of this flaw to execute arbitrary SQL commands and for privilege
escalation.");

  script_tag(name:"affected", value:"'cyrus-sasl2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
2.1.27~101-g0780600+dfsg-3+deb9u2.

We recommend that you upgrade your cyrus-sasl2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-db", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-heimdal", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.27~101-g0780600+dfsg-3+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
