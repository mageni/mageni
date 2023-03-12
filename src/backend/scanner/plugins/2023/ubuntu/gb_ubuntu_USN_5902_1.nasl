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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5902.1");
  script_cve_id("CVE-2023-0567", "CVE-2023-0568", "CVE-2023-0662");
  script_tag(name:"creation_date", value:"2023-03-02 04:10:54 +0000 (Thu, 02 Mar 2023)");
  script_version("2023-03-06T10:10:02+0000");
  script_tag(name:"last_modification", value:"2023-03-06 10:10:02 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 18:02:00 +0000 (Fri, 03 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-5902-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5902-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5902-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.2, php7.4, php8.1' package(s) announced via the USN-5902-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP incorrectly handled certain invalid Blowfish
password hashes. An invalid password hash could possibly allow applications
to accept any password as valid, contrary to expectations. (CVE-2023-0567)

It was discovered that PHP incorrectly handled resolving long paths. A
remote attacker could possibly use this issue to obtain or modify sensitive
information. (CVE-2023-0568)

It was discovered that PHP incorrectly handled a large number of parts in
HTTP form uploads. A remote attacker could possibly use this issue to cause
PHP to consume resources, leading to a denial of service. (CVE-2023-0662)");

  script_tag(name:"affected", value:"'php7.2, php7.4, php8.1' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.2", ver:"7.2.24-0ubuntu0.18.04.17", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.2-cgi", ver:"7.2.24-0ubuntu0.18.04.17", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.2-cli", ver:"7.2.24-0ubuntu0.18.04.17", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.2-fpm", ver:"7.2.24-0ubuntu0.18.04.17", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.2", ver:"7.2.24-0ubuntu0.18.04.17", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.4", ver:"7.4.3-4ubuntu2.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cgi", ver:"7.4.3-4ubuntu2.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cli", ver:"7.4.3-4ubuntu2.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-fpm", ver:"7.4.3-4ubuntu2.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4", ver:"7.4.3-4ubuntu2.18", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php8.1", ver:"8.1.2-1ubuntu2.11", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-cgi", ver:"8.1.2-1ubuntu2.11", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-cli", ver:"8.1.2-1ubuntu2.11", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-fpm", ver:"8.1.2-1ubuntu2.11", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1", ver:"8.1.2-1ubuntu2.11", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php8.1", ver:"8.1.7-1ubuntu3.3", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-cgi", ver:"8.1.7-1ubuntu3.3", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-cli", ver:"8.1.7-1ubuntu3.3", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-fpm", ver:"8.1.7-1ubuntu3.3", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1", ver:"8.1.7-1ubuntu3.3", rls:"UBUNTU22.10"))) {
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
