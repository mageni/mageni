# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1425");
  script_version("2020-01-23T11:44:52+0000");
  script_cve_id("CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416", "CVE-2018-8740");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:44:52 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:44:52 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for sqlite (EulerOS-SA-2019-1425)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1425");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'sqlite' package(s) announced via the EulerOS-SA-2019-1425 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that SQLite's sqlite3VdbeExec() function did not properly implement comparison operators. A local attacker could submit a specially crafted CHECK statement that would crash the SQLite process, or have other unspecified impacts.(CVE-2015-3415)

A flaw was found in the way SQLite handled dequoting of collation-sequence names. A local attacker could submit a specially crafted COLLATE statement that would crash the SQLite process, or have other unspecified impacts.(CVE-2015-3414)

A NULL pointer dereference vulnerability was found in SQLite. Loading a database whose schema was corrupted using a CREATE TABLE AS statement would result in a SQLite crash.(CVE-2018-8740)

It was found that SQLite's sqlite3VXPrintf() function did not properly handle precision and width values during floating-point conversions. A local attacker could submit a specially crafted SELECT statement that would crash the SQLite process, or have other unspecified impacts.(CVE-2015-3416)");

  script_tag(name:"affected", value:"'sqlite' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"sqlite", rpm:"sqlite~3.7.17~8.h2.eulerosv2r7", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-devel", rpm:"sqlite-devel~3.7.17~8.h2.eulerosv2r7", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);