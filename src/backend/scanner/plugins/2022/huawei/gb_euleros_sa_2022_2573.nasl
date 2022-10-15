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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2573");
  script_cve_id("CVE-2021-27928", "CVE-2021-46657", "CVE-2021-46658", "CVE-2021-46659", "CVE-2021-46661", "CVE-2021-46662", "CVE-2021-46663", "CVE-2021-46664", "CVE-2021-46665", "CVE-2021-46666", "CVE-2021-46667", "CVE-2021-46668", "CVE-2022-27377", "CVE-2022-27378", "CVE-2022-27380", "CVE-2022-27381", "CVE-2022-27383", "CVE-2022-27384", "CVE-2022-27385", "CVE-2022-27386", "CVE-2022-27387", "CVE-2022-27445", "CVE-2022-27448", "CVE-2022-27455", "CVE-2022-27457", "CVE-2022-31621", "CVE-2022-31622", "CVE-2022-31623", "CVE-2022-31624");
  script_tag(name:"creation_date", value:"2022-10-12 04:41:33 +0000 (Wed, 12 Oct 2022)");
  script_version("2022-10-12T10:13:47+0000");
  script_tag(name:"last_modification", value:"2022-10-12 10:13:47 +0000 (Wed, 12 Oct 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-21 13:54:00 +0000 (Thu, 21 Apr 2022)");

  script_name("Huawei EulerOS: Security Advisory for mariadb (EulerOS-SA-2022-2573)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2573");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2573");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mariadb' package(s) announced via the EulerOS-SA-2022-2573 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue in the component Item_subselect::init_expr_cache_tracker of MariaDB Server v10.6 and below was discovered to allow attackers to cause a Denial of Service (DoS) via specially crafted SQL statements.(CVE-2022-27384)

MariaDB Server before 10.7 is vulnerable to Denial of Service. In extra/mariabackup/ds_compress.cc, when an error occurs (pthread_create returns a nonzero value) while executing the method create_worker_threads, the held lock is not released correctly, which allows local users to trigger a denial of service due to the deadlock.(CVE-2022-31622)

MariaDB Server before 10.7 is vulnerable to Denial of Service. In extra/mariabackup/ds_compress.cc, when an error occurs (i.e., going to the err label) while executing the method create_worker_threads, the held lock thd->ctrl_mutex is not released correctly, which allows local users to trigger a denial of service due to the deadlock.(CVE-2022-31623)

MariaDB Server before 10.7 is vulnerable to Denial of Service. In extra/mariabackup/ds_xbstream.cc, when an error occurs (stream_ctxt->dest_file == NULL) while executing the method xbstream_open, the held lock is not released correctly, which allows local users to trigger a denial of service due to the deadlock.(CVE-2022-31621)

MariaDB Server before 10.7 is vulnerable to Denial of Service. While executing the plugin/server_audit/server_audit.c method log_statement_ex, the held lock lock_bigbuffer is not released correctly, which allows local users to trigger a denial of service due to the deadlock.(CVE-2022-31624)

save_window_function_values in MariaDB before 10.6.3 allows an application crash because of incorrect handling of with_window_func=true for a subquery.(CVE-2021-46658)

MariaDB through 10.5.9 allows a set_var.cc application crash via certain uses of an UPDATE statement in conjunction with a nested subquery.(CVE-2021-46662)

There is an Assertion failure in MariaDB Server v10.9 and below via 'node->pcur->rel_pos == BTR_PCUR_ON' at /row/row0mysql.cc.(CVE-2022-27448)

MariaDB Server v10.9 and below was discovered to contain a segmentation fault via the component sql/sql_window.cc.(CVE-2022-27445)

An issue in the component Used_tables_and_const_cache::used_tables_and_const_cache_join of MariaDB Server v10.7 and below was discovered to allow attackers to cause a Denial of Service (DoS) via specially crafted SQL statements.(CVE-2022-27385)

MariaDB Server v10.7 and below was discovered to contain a segmentation fault via the component sql/sql_class.cc.(CVE-2022-27386)

MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component my_wildcmp_8bit_impl at /strings/ctype-simple.c.(CVE-2022-27455)

MariaDB Server v10.6 and below was discovered to contain an use-after-free in the component my_strcasecmp_8bit, which is exploited via specially crafted SQL statements.(CVE-2022-27383)

MariaDB Server v10.7 and below was discovered to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mariadb' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.3.9~2.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common", rpm:"mariadb-common~10.3.9~2.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~10.3.9~2.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
