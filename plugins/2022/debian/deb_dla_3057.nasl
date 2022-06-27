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
  script_oid("1.3.6.1.4.1.25623.1.0.893057");
  script_version("2022-06-24T14:04:41+0000");
  script_cve_id("CVE-2021-38562");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-06-24 14:04:41 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-21 17:00:00 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2022-06-24 01:00:09 +0000 (Fri, 24 Jun 2022)");
  script_name("Debian LTS: Security Advisory for request-tracker4 (DLA-3057-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/06/msg00019.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3057-1");
  script_xref(name:"Advisory-ID", value:"DLA-3057-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/995175");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'request-tracker4'
  package(s) announced via the DLA-3057-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an issue in request-tracker4, a
extensible ticket/issue tracking system. Sensitive information
could have been revealed by way of a timing attack on the
authentication system.");

  script_tag(name:"affected", value:"'request-tracker4' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', this problem has been fixed in version
4.4.1-3+deb9u4.

We recommend that you upgrade your request-tracker4 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.4.1-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.4.1-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.4.1-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.4.1-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.4.1-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.4.1-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rt4-doc-html", ver:"4.4.1-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.4.1-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.4.1-3+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
