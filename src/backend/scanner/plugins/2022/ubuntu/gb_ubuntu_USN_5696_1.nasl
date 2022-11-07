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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5696.1");
  script_cve_id("CVE-2022-21589", "CVE-2022-21592", "CVE-2022-21594", "CVE-2022-21599", "CVE-2022-21604", "CVE-2022-21608", "CVE-2022-21611", "CVE-2022-21617", "CVE-2022-21625", "CVE-2022-21632", "CVE-2022-21633", "CVE-2022-21637", "CVE-2022-21640", "CVE-2022-39400", "CVE-2022-39408", "CVE-2022-39410");
  script_tag(name:"creation_date", value:"2022-10-25 04:48:39 +0000 (Tue, 25 Oct 2022)");
  script_version("2022-10-25T10:13:35+0000");
  script_tag(name:"last_modification", value:"2022-10-25 10:13:35 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 21:18:00 +0000 (Tue, 18 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5696-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5696-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5696-1");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-40.html");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-31.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.7, mysql-8.0' package(s) announced via the USN-5696-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.31 in Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
Ubuntu 18.04 LTS has been updated to MySQL 5.7.40.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:

[link moved to references]
[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.7, mysql-8.0' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.7", ver:"5.7.40-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.31-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.31-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
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
