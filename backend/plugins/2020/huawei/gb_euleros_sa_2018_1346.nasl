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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1346");
  script_version("2020-01-23T11:22:40+0000");
  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384", "CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3651", "CVE-2017-3653", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:22:40 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:22:40 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for mariadb (EulerOS-SA-2018-1346)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1346");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'mariadb' package(s) announced via the EulerOS-SA-2018-1346 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mysql: Client programs unspecified vulnerability (CPU Jul 2017) (CVE-2017-3636)

mysql: Server: DML unspecified vulnerability (CPU Jul 2017) (CVE-2017-3641)

mysql: Client mysqldump unspecified vulnerability (CPU Jul 2017) (CVE-2017-3651)

mysql: Server: Replication unspecified vulnerability (CPU Oct 2017) (CVE-2017-10268)

mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2017) (CVE-2017-10378)

mysql: Client programs unspecified vulnerability (CPU Oct 2017) (CVE-2017-10379)

mysql: Server: DDL unspecified vulnerability (CPU Oct 2017) (CVE-2017-10384)

mysql: Server: DDL unspecified vulnerability (CPU Jan 2018) (CVE-2018-2622)

mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018) (CVE-2018-2640)

mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018) (CVE-2018-2665)

mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018) (CVE-2018-2668)

mysql: Server: Replication unspecified vulnerability (CPU Apr 2018) (CVE-2018-2755)

mysql: Client programs unspecified vulnerability (CPU Apr 2018) (CVE-2018-2761)

mysql: Server: Locking unspecified vulnerability (CPU Apr 2018) (CVE-2018-2771)

mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2018) (CVE-2018-2781)

mysql: Server: DDL unspecified vulnerability (CPU Apr 2018) (CVE-2018-2813)

mysql: Server: DDL unspecified vulnerability (CPU Apr 2018) (CVE-2018-2817)

mysql: InnoDB unspecified vulnerability (CPU Apr 2018) (CVE-2018-2819)

mysql: Server: DDL unspecified vulnerability (CPU Jul 2017) (CVE-2017-3653)

mysql: use of SSL/TLS not enforced in libmysqld (Return of BACKRONYM) (CVE-2018-2767)");

  script_tag(name:"affected", value:"'mariadb' package(s) on Huawei EulerOS Virtualization 2.5.0.");

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

if(release == "EULEROSVIRT-2.5.0") {

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.60~1.h1", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.60~1.h1", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.60~1.h1", rls:"EULEROSVIRT-2.5.0"))) {
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