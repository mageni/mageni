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
  script_oid("1.3.6.1.4.1.25623.1.0.704814");
  script_version("2020-12-18T04:00:11+0000");
  script_cve_id("CVE-2018-1311");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-12-18 11:55:37 +0000 (Fri, 18 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-18 04:00:11 +0000 (Fri, 18 Dec 2020)");
  script_name("Debian: Security Advisory for xerces-c (DSA-4814-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4814.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4814-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-c'
  package(s) announced via the DSA-4814-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that xerces-c, a validating XML parser library for
C++, did not correctly scan DTDs. The use-after-free vulnerability
resulting from this issue would allow a remote attacker to leverage a
specially crafted XML file in order to crash the application or
potentially execute arbitrary code.
Please note that the patch fixing this issue comes at the expense of a
newly introduced memory leak.");

  script_tag(name:"affected", value:"'xerces-c' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), this problem has been fixed in
version 3.2.2+debian-1+deb10u1.

We recommend that you upgrade your xerces-c packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-dev", ver:"3.2.2+debian-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-doc", ver:"3.2.2+debian-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-samples", ver:"3.2.2+debian-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxerces-c3.2", ver:"3.2.2+debian-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
