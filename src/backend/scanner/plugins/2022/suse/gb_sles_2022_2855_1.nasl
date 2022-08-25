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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2855.1");
  script_cve_id("CVE-2021-22930", "CVE-2021-22940", "CVE-2021-22959", "CVE-2021-22960", "CVE-2022-32212", "CVE-2022-32213", "CVE-2022-32214", "CVE-2022-32215");
  script_tag(name:"creation_date", value:"2022-08-22 04:48:53 +0000 (Mon, 22 Aug 2022)");
  script_version("2022-08-22T10:11:10+0000");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-18 17:15:00 +0000 (Mon, 18 Oct 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2855-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2855-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222855-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs10' package(s) announced via the SUSE-SU-2022:2855-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs10 fixes the following issues:

CVE-2021-22930, CVE-2021-22940: Fixed two memory corruption issues
 during HTTP/2 stream cancellation (bsc#1188917, bsc#1189368).

CVE-2022-32213, CVE-2022-32214, CVE-2022-32215, CVE-2021-22960,
 CVE-2021-22959: Fixed multiple HTTP request smuggling issues in the
 underlying HTTP parser (bsc#1201325, bsc#1201326, bsc#1201327,
 bsc#1191602, bsc#1191601).

CVE-2022-32212: Fixed a DNS rebinding issue caused by improper IPv4
 validation (bsc#1201328).");

  script_tag(name:"affected", value:"'nodejs10' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.24.1~150000.1.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.24.1~150000.1.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.24.1~150000.1.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.24.1~150000.1.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.24.1~150000.1.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.24.1~150000.1.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.24.1~150000.1.47.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.24.1~150000.1.47.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.24.1~150000.1.47.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.24.1~150000.1.47.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.24.1~150000.1.47.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.24.1~150000.1.47.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.24.1~150000.1.47.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.24.1~150000.1.47.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.24.1~150000.1.47.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.24.1~150000.1.47.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.24.1~150000.1.47.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.24.1~150000.1.47.1", rls:"SLES15.0SP2"))) {
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
