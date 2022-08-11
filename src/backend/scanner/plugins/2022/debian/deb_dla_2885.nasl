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
  script_oid("1.3.6.1.4.1.25623.1.0.892885");
  script_version("2022-01-24T02:00:13+0000");
  script_cve_id("CVE-2021-3481", "CVE-2021-45930");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-01-24 11:12:31 +0000 (Mon, 24 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-24 02:00:13 +0000 (Mon, 24 Jan 2022)");
  script_name("Debian LTS: Security Advisory for qtsvg-opensource-src (DLA-2885-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/01/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2885-1");
  script_xref(name:"Advisory-ID", value:"DLA-2885-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/986798");
  script_xref(name:"URL", value:"https://bugs.debian.org/1002991");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qtsvg-opensource-src'
  package(s) announced via the DLA-2885-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple out-of-bounds errors were discovered in qtsvg-opensource-src.
The highest threat from CVE-2021-3481 (at least) is to data
confidentiality the application availability.");

  script_tag(name:"affected", value:"'qtsvg-opensource-src' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
5.7.1~20161021-2.1+deb9u1.

We recommend that you upgrade your qtsvg-opensource-src packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libqt5svg5", ver:"5.7.1~20161021-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5svg5-dev", ver:"5.7.1~20161021-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtsvg5-dbg", ver:"5.7.1~20161021-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtsvg5-doc", ver:"5.7.1~20161021-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtsvg5-doc-html", ver:"5.7.1~20161021-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtsvg5-examples", ver:"5.7.1~20161021-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
