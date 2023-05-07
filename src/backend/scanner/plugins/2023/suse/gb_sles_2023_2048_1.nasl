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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2048.1");
  script_cve_id("CVE-2021-3541", "CVE-2022-29824", "CVE-2023-28484", "CVE-2023-29469");
  script_tag(name:"creation_date", value:"2023-04-27 04:18:08 +0000 (Thu, 27 Apr 2023)");
  script_version("2023-05-05T09:09:19+0000");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-03 20:23:00 +0000 (Wed, 03 May 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2048-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2048-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232048-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2023:2048-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxml2 fixes the following issues:

CVE-2023-29469: Fixed inconsistent result when hashing empty strings (bsc#1210412).
CVE-2023-28484: Fixed NULL pointer dereference in xmlSchemaFixupComplexType (bsc#1210411).
CVE-2022-29824: Fixed integer overflow leading to out-of-bounds write in buf.c (bsc#1199132).

The following non-security bugs were fixed:

Added W3C conformance tests to the testsuite (bsc#1204585).
Fixed NULL pointer dereference when parsing invalid data (glgo#libxml2!15) (bsc#1065270) .");

  script_tag(name:"affected", value:"'libxml2' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit-debuginfo", rpm:"libxml2-2-32bit-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-python-debugsource", rpm:"python-libxml2-python-debugsource~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-libxml2-python", rpm:"python2-libxml2-python~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-libxml2-python-debuginfo", rpm:"python2-libxml2-python-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-python", rpm:"python3-libxml2-python~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-python-debuginfo", rpm:"python3-libxml2-python-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit-debuginfo", rpm:"libxml2-2-32bit-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-python-debugsource", rpm:"python-libxml2-python-debugsource~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-libxml2-python", rpm:"python2-libxml2-python~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-libxml2-python-debuginfo", rpm:"python2-libxml2-python-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-python", rpm:"python3-libxml2-python~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-python-debuginfo", rpm:"python3-libxml2-python-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit-debuginfo", rpm:"libxml2-2-32bit-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-python-debugsource", rpm:"python-libxml2-python-debugsource~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-python", rpm:"python3-libxml2-python~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-python-debuginfo", rpm:"python3-libxml2-python-debuginfo~2.9.7~150000.3.57.1", rls:"SLES15.0SP3"))) {
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
