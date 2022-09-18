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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.3957.2");
  script_cve_id("CVE-2019-2614", "CVE-2019-2627");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-05 17:11:00 +0000 (Fri, 05 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-3957-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3957-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3957-2");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-5564-changelog/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-5564-release-notes/");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-26.html");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb-5.5' package(s) announced via the USN-3957-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3957-1 fixed multiple vulnerabilities in MySQL. This update provides the
 corresponding fixes for CVE-2019-2614 and CVE-2019-2627 in MariaDB 5.5.

Ubuntu 14.04 LTS has been updated to MariaDB 5.5.64.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]

 Original advisory details:

 Multiple security issues were discovered in MySQL and this update includes
 a new upstream MySQL version to fix these issues.

 Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 18.10, and Ubuntu 19.04 have
 been updated to MySQL 5.7.26.

 In addition to security fixes, the updated packages contain bug fixes, new
 features, and possibly incompatible changes.

 Please see the following for more information:
 [link moved to references]
 [link moved to references]");

  script_tag(name:"affected", value:"'mariadb-5.5' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server", ver:"5.5.64-1ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
