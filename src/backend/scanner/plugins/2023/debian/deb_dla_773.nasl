# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2017.773");
  script_cve_id("CVE-2013-7459");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DLA-773)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-773");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-773-4");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-crypto' package(s) announced via the DLA-773 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The previous security updates for python-crypto (DLA-773-1, DLA-773-2 & DLA-773-3) were not available on non-amd64 architectures.

This was due to the testsuite failing to exit gracefully when multiprocessing based tests were not functioning or available, such as on the Debian buildd network.

For Debian 7 Wheezy, this issue has been fixed in python-crypto version 2.6-4+deb7u7. There has been no change to the codepath associated with the original CVE (2013-7459).");

  script_tag(name:"affected", value:"'python-crypto' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"python-crypto-dbg", ver:"2.6-4+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-crypto-doc", ver:"2.6-4+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-crypto", ver:"2.6-4+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-crypto-dbg", ver:"2.6-4+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-crypto", ver:"2.6-4+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
