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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5840.1");
  script_cve_id("CVE-2018-5786", "CVE-2020-25467", "CVE-2021-27345", "CVE-2021-27347", "CVE-2022-26291", "CVE-2022-28044");
  script_tag(name:"creation_date", value:"2023-02-03 04:10:38 +0000 (Fri, 03 Feb 2023)");
  script_version("2023-02-03T10:10:17+0000");
  script_tag(name:"last_modification", value:"2023-02-03 10:10:17 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 13:01:00 +0000 (Fri, 22 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5840-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5840-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5840-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lrzip' package(s) announced via the USN-5840-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Long Range ZIP incorrectly handled pointers. If
a user or an automated system were tricked into opening a certain
specially crafted ZIP file, an attacker could possibly use this issue
to cause a denial of service. This issue only affected Ubuntu 14.04 ESM,
Ubuntu 16.04 ESM, Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS. (CVE-2020-25467)

It was discovered that Long Range ZIP incorrectly handled pointers. If
a user or an automated system were tricked into opening a certain
specially crafted ZIP file, an attacker could possibly use this issue
to cause a denial of service. This issue only affected Ubuntu 18.04 LTS
and Ubuntu 20.04 LTS. (CVE-2021-27345, CVE-2021-27347)

It was discovered that Long Range ZIP incorrectly handled pointers. If
a user or an automated system were tricked into opening a certain
specially crafted ZIP file, an attacker could possibly use this issue
to cause a denial of service. This issue only affected Ubuntu 16.04 ESM,
Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS. (CVE-2022-26291)

It was discovered that Long Range ZIP incorrectly handled memory allocation,
which could lead to a heap memory corruption. An attacker could possibly use
this issue to cause denial of service. This issue affected Ubuntu 14.04 ESM,
Ubuntu 16.04 ESM, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and
Ubuntu 22.10. (CVE-2022-28044)");

  script_tag(name:"affected", value:"'lrzip' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"lrzip", ver:"0.616-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lrzip", ver:"0.621-1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lrzip", ver:"0.631-1+deb9u3build0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"lrzip", ver:"0.631+git180528-1+deb10u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"lrzip", ver:"0.651-2ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"lrzip", ver:"0.651-2ubuntu0.22.10.1", rls:"UBUNTU22.10"))) {
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
