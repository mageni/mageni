# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1860.1");
  script_cve_id("CVE-2018-25009", "CVE-2018-25010", "CVE-2018-25011", "CVE-2018-25012", "CVE-2018-25013", "CVE-2020-36328", "CVE-2020-36329", "CVE-2020-36330", "CVE-2020-36331", "CVE-2020-36332");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-09T14:56:37+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 12:15:00 +0000 (Fri, 11 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1860-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0|SLES15\.0SP3|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1860-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211860-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwebp' package(s) announced via the SUSE-SU-2021:1860-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libwebp fixes the following issues:

CVE-2018-25010: Fixed heap-based buffer overflow in ApplyFilter()
 (bsc#1185685).

CVE-2020-36330: Fixed heap-based buffer overflow in
 ChunkVerifyAndAssign() (bsc#1185691).

CVE-2020-36332: Fixed extreme memory allocation when reading a file
 (bsc#1185674).

CVE-2020-36329: Fixed use-after-free in EmitFancyRGB() (bsc#1185652).

CVE-2018-25012: Fixed heap-based buffer overflow in GetLE24()
 (bsc#1185690).

CVE-2020-36328: Fixed heap-based buffer overflow in WebPDecode*Into
 functions (bsc#1185688).

CVE-2018-25013: Fixed heap-based buffer overflow in ShiftBytes()
 (bsc#1185654).

CVE-2020-36331: Fixed heap-based buffer overflow in ChunkAssignData()
 (bsc#1185686).

CVE-2018-25009: Fixed heap-based buffer overflow in GetLE16()
 (bsc#1185673).

CVE-2018-25011: Fixed fail on multiple image chunks (bsc#1186247).");

  script_tag(name:"affected", value:"'libwebp' package(s) on SUSE Manager Server 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Proxy 4.0, SUSE Linux Enterprise Workstation Extension 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15, SUSE Enterprise Storage 6, SUSE CaaS Platform 4.0");

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
  if(!isnull(res = isrpmvuln(pkg:"libwebp-debugsource", rpm:"libwebp-debugsource~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6", rpm:"libwebp6~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6-debuginfo", rpm:"libwebp6-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder2", rpm:"libwebpdecoder2~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder2-debuginfo", rpm:"libwebpdecoder2-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2", rpm:"libwebpdemux2~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-debuginfo", rpm:"libwebpdemux2-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpextras0", rpm:"libwebpextras0~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpextras0-debuginfo", rpm:"libwebpextras0-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux2", rpm:"libwebpmux2~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux2-debuginfo", rpm:"libwebpmux2-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-debugsource", rpm:"libwebp-debugsource~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6", rpm:"libwebp6~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6-debuginfo", rpm:"libwebp6-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder2", rpm:"libwebpdecoder2~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder2-debuginfo", rpm:"libwebpdecoder2-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2", rpm:"libwebpdemux2~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-debuginfo", rpm:"libwebpdemux2-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpextras0", rpm:"libwebpextras0~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpextras0-debuginfo", rpm:"libwebpextras0-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux2", rpm:"libwebpmux2~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux2-debuginfo", rpm:"libwebpmux2-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP1"))){
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {
  if(!isnull(res = isrpmvuln(pkg:"libwebp-debugsource", rpm:"libwebp-debugsource~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6", rpm:"libwebp6~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6-debuginfo", rpm:"libwebp6-debuginfo~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder2", rpm:"libwebpdecoder2~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder2-debuginfo", rpm:"libwebpdecoder2-debuginfo~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2", rpm:"libwebpdemux2~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-debuginfo", rpm:"libwebpdemux2-debuginfo~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpextras0", rpm:"libwebpextras0~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpextras0-debuginfo", rpm:"libwebpextras0-debuginfo~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux2", rpm:"libwebpmux2~0.5.0~3.5.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux2-debuginfo", rpm:"libwebpmux2-debuginfo~0.5.0~3.5.1", rls:"SLES15.0"))){
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
  if(!isnull(res = isrpmvuln(pkg:"libwebp-debugsource", rpm:"libwebp-debugsource~0.5.0~3.5.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6-32bit", rpm:"libwebp6-32bit~0.5.0~3.5.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6-32bit-debuginfo", rpm:"libwebp6-32bit-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP3"))){
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
  if(!isnull(res = isrpmvuln(pkg:"libwebp-debugsource", rpm:"libwebp-debugsource~0.5.0~3.5.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6-32bit", rpm:"libwebp6-32bit~0.5.0~3.5.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp6-32bit-debuginfo", rpm:"libwebp6-32bit-debuginfo~0.5.0~3.5.1", rls:"SLES15.0SP2"))){
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
