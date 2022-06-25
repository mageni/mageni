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
  script_oid("1.3.6.1.4.1.25623.1.0.844679");
  script_version("2020-10-29T06:27:27+0000");
  script_cve_id("CVE-2019-14775", "CVE-2020-14672", "CVE-2020-14760", "CVE-2020-14765", "CVE-2020-14769", "CVE-2020-14771", "CVE-2020-14773", "CVE-2020-14775", "CVE-2020-14776", "CVE-2020-14777", "CVE-2020-14785", "CVE-2020-14786", "CVE-2020-14789", "CVE-2020-14790", "CVE-2020-14791", "CVE-2020-14793", "CVE-2020-14794", "CVE-2020-14800", "CVE-2020-14804", "CVE-2020-14809", "CVE-2020-14812", "CVE-2020-14814", "CVE-2020-14821", "CVE-2020-14827", "CVE-2020-14828", "CVE-2020-14829", "CVE-2020-14830", "CVE-2020-14836", "CVE-2020-14837", "CVE-2020-14838", "CVE-2020-14839", "CVE-2020-14844", "CVE-2020-14845", "CVE-2020-14846", "CVE-2020-14848", "CVE-2020-14852", "CVE-2020-14853", "CVE-2020-14860", "CVE-2020-14861", "CVE-2020-14866", "CVE-2020-14867", "CVE-2020-14868", "CVE-2020-14869", "CVE-2020-14870", "CVE-2020-14873", "CVE-2020-14878", "CVE-2020-14888", "CVE-2020-14891", "CVE-2020-14893");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-29 11:17:52 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-28 04:00:24 +0000 (Wed, 28 Oct 2020)");
  script_name("Ubuntu: Security Advisory for mysql-8.0 (USN-4604-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU20\.04 LTS|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.10)");

  script_xref(name:"USN", value:"4604-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-October/005722.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-8.0'
  package(s) announced via the USN-4604-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.22 in Ubuntu 20.04 LTS and Ubuntu 20.10.
Ubuntu 16.04 LTS and Ubuntu 18.04 LTS have been updated to MySQL 5.7.32.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.");

  script_tag(name:"affected", value:"'mysql-8.0' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.22-0ubuntu0.20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.7", ver:"5.7.32-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.7", ver:"5.7.32-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.22-0ubuntu0.20.10.2", rls:"UBUNTU20.10"))) {
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
