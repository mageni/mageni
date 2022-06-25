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
  script_oid("1.3.6.1.4.1.25623.1.0.892525");
  script_version("2021-01-16T04:00:14+0000");
  script_cve_id("CVE-2018-19840", "CVE-2018-19841", "CVE-2019-1010315", "CVE-2019-1010317", "CVE-2019-1010319", "CVE-2019-11498", "CVE-2020-35738");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-01-18 11:03:31 +0000 (Mon, 18 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-16 04:00:14 +0000 (Sat, 16 Jan 2021)");
  script_name("Debian LTS: Security Advisory for wavpack (DLA-2525-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00013.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2525-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/915564");
  script_xref(name:"URL", value:"https://bugs.debian.org/915565");
  script_xref(name:"URL", value:"https://bugs.debian.org/932060");
  script_xref(name:"URL", value:"https://bugs.debian.org/932061");
  script_xref(name:"URL", value:"https://bugs.debian.org/927903");
  script_xref(name:"URL", value:"https://bugs.debian.org/978548");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wavpack'
  package(s) announced via the DLA-2525-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities in wavpack were found, like OOB read
(which could potentially lead to a DOS attack), unexpected
control flow, crashes, integer overflow, and segfaults.");

  script_tag(name:"affected", value:"'wavpack' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
5.0.0-2+deb9u3.

We recommend that you upgrade your wavpack packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libwavpack-dev", ver:"5.0.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwavpack1", ver:"5.0.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wavpack", ver:"5.0.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
