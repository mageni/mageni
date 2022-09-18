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
  script_oid("1.3.6.1.4.1.25623.1.0.893106");
  script_version("2022-09-15T10:11:07+0000");
  script_cve_id("CVE-2022-0718");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:07 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-14 01:00:10 +0000 (Wed, 14 Sep 2022)");
  script_name("Debian LTS: Security Advisory for python-oslo.utils (DLA-3106-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/09/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3106-1");
  script_xref(name:"Advisory-ID", value:"DLA-3106-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-oslo.utils'
  package(s) announced via the DLA-3106-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was credential disclosure vulnerability
python-oslo.utils, a set of utilities used by OpenStack.");

  script_tag(name:"affected", value:"'python-oslo.utils' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
3.36.5-0+deb10u2.

We recommend that you upgrade your python-oslo.utils packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-oslo.utils", ver:"3.36.5-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-oslo.utils-doc", ver:"3.36.5-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-oslo.utils", ver:"3.36.5-0+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
