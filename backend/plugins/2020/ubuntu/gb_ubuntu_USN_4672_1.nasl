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
  script_oid("1.3.6.1.4.1.25623.1.0.844762");
  script_version("2020-12-22T06:30:14+0000");
  script_cve_id("CVE-2018-1000035", "CVE-2018-18384", "CVE-2019-13232", "CVE-2014-9913", "CVE-2016-9844");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-12-22 06:30:14 +0000 (Tue, 22 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-17 04:00:45 +0000 (Thu, 17 Dec 2020)");
  script_name("Ubuntu: Security Advisory for unzip (USN-4672-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"USN", value:"4672-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-December/005812.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip'
  package(s) announced via the USN-4672-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rene Freingruber discovered that unzip incorrectly handled certain
specially crafted password protected ZIP archives. If a user or automated
system using unzip were tricked into opening a specially crafted zip file,
an attacker could exploit this to cause a crash, resulting in a denial of
service. (CVE-2018-1000035)

Antonio Carista discovered that unzip incorrectly handled certain
specially crafted ZIP archives. If a user or automated system using unzip
were tricked into opening a specially crafted zip file, an attacker could
exploit this to cause a crash, resulting in a denial of service. This
issue only affected Ubuntu 12.04 ESM and Ubuntu 14.04 ESM.
(CVE-2018-18384)

It was discovered that unzip incorrectly handled certain specially crafted
ZIP archives. If a user or automated system using unzip were tricked into
opening a specially crafted zip file, an attacker could exploit this to
cause resource consumption, resulting in a denial of service.
(CVE-2019-13232)

Martin Carpenter discovered that unzip incorrectly handled certain
specially crafted ZIP archives. If a user or automated system using unzip
were tricked into opening a specially crafted zip file, an attacker could
exploit this to cause a crash, resulting in a denial of service. This
issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM and Ubuntu 16.04
LTS. (CVE-2014-9913)

Alexis Vanden Eijnde discovered that unzip incorrectly handled certain
specially crafted ZIP archives. If a user or automated system using unzip
were tricked into opening a specially crafted zip file, an attacker could
exploit this to cause a crash, resulting in a denial of service. This
issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM and Ubuntu 16.04
LTS. (CVE-2016-9844)");

  script_tag(name:"affected", value:"'unzip' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"unzip", ver:"6.0-21ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"unzip", ver:"6.0-20ubuntu1.1", rls:"UBUNTU16.04 LTS"))) {
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