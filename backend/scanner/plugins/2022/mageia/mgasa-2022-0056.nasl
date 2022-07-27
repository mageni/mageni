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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0056");
  script_cve_id("CVE-2021-3850");
  script_tag(name:"creation_date", value:"2022-02-13 03:19:42 +0000 (Sun, 13 Feb 2022)");
  script_version("2022-02-13T03:19:42+0000");
  script_tag(name:"last_modification", value:"2022-02-14 11:09:18 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-28 21:15:00 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0056)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0056");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0056.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30008");
  script_xref(name:"URL", value:"https://github.com/ADOdb/ADOdb/releases/tag/v5.20.21");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-adodb' package(s) announced via the MGASA-2022-0056 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security hotfix release addressing a critical vulnerability in PostgreSQL
connections (CVE-2021-3850)

Additional fixes:
Fix usage of get_magic_* functions #619 #657
Fix PHP warning in _rs2rs() function #679
pdo: Fix Fatal error in _query() #666
pdo: Fix undefined variable #678
pgsql: Fix Fatal error in _close() method (PHP8) #666
pgsql: fix deprecated function aliases (PHP8) #667
text: fix Cannot pass parameter by reference #668
Add support for persistent connections in PDO driver #650
Connect to SQL Server database on a specified port. #624
DSN database connection with password containing # fails #651
Metacolumns returns wrong type for integer fields in Mysql 8 #642
Uninitialized Variable access in mssqlnative ErrorNo() method #637");

  script_tag(name:"affected", value:"'php-adodb' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"php-adodb", rpm:"php-adodb~5.20.21~1.mga8", rls:"MAGEIA8"))) {
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
