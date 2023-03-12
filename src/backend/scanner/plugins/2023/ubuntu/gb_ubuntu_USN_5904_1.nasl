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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5904.1");
  script_cve_id("CVE-2019-13590", "CVE-2021-23159", "CVE-2021-23172", "CVE-2021-23210", "CVE-2021-33844", "CVE-2021-3643", "CVE-2021-40426", "CVE-2022-31650", "CVE-2022-31651");
  script_tag(name:"creation_date", value:"2023-03-03 04:37:35 +0000 (Fri, 03 Mar 2023)");
  script_version("2023-03-03T10:59:40+0000");
  script_tag(name:"last_modification", value:"2023-03-03 10:59:40 +0000 (Fri, 03 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-10 17:00:00 +0000 (Tue, 10 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5904-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5904-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5904-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sox' package(s) announced via the USN-5904-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Helmut Grohne discovered that SoX incorrectly handled certain inputs. If a
user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS,
and Ubuntu 18.04 LTS. (CVE-2019-13590)

Helmut Grohne discovered that SoX incorrectly handled certain inputs. If a
user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to cause a
denial of service. (CVE-2021-23159, CVE-2021-23172, CVE-2021-23210,
CVE-2021-33844, CVE-2021-3643, CVE-2021-40426, CVE-2022-31650, and
CVE-2022-31651)");

  script_tag(name:"affected", value:"'sox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsox2", ver:"14.4.1-3ubuntu1.1+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sox", ver:"14.4.1-3ubuntu1.1+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsox2", ver:"14.4.1-5+deb8u4ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sox", ver:"14.4.1-5+deb8u4ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsox3", ver:"14.4.2-3ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sox", ver:"14.4.2-3ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsox3", ver:"14.4.2+git20190427-2+deb11u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sox", ver:"14.4.2+git20190427-2+deb11u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsox3", ver:"14.4.2+git20190427-2+deb11u1build0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sox", ver:"14.4.2+git20190427-2+deb11u1build0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsox3", ver:"14.4.2+git20190427-3ubuntu0.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sox", ver:"14.4.2+git20190427-3ubuntu0.1", rls:"UBUNTU22.10"))) {
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
