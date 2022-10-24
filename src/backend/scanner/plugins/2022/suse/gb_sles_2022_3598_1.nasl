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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3598.1");
  script_cve_id("CVE-2018-10772", "CVE-2018-18915", "CVE-2018-5772", "CVE-2018-8976", "CVE-2018-8977", "CVE-2020-18898", "CVE-2020-18899", "CVE-2021-29470", "CVE-2021-31291", "CVE-2021-31292", "CVE-2021-32617", "CVE-2021-37618", "CVE-2021-37619", "CVE-2021-37620", "CVE-2021-37621");
  script_tag(name:"creation_date", value:"2022-10-18 04:52:04 +0000 (Tue, 18 Oct 2022)");
  script_version("2022-10-18T10:13:37+0000");
  script_tag(name:"last_modification", value:"2022-10-18 10:13:37 +0000 (Tue, 18 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-04 00:55:00 +0000 (Wed, 04 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3598-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3598-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223598-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the SUSE-SU-2022:3598-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exiv2 fixes the following issues:

CVE-2021-37621: Fixed denial of service due to infinite loop in
 Image:printIFDStructure (bsc#1189333).

CVE-2021-37620: Fixed out-of-bounds read in XmpTextValue:read()
 (bsc#1189332).

CVE-2021-37619: Fixed out-of-bounds read in
 Exiv2:Jp2Image:encodeJp2Header (bsc#1189331).

CVE-2021-37618: Fixed out-of-bounds read in
 Exiv2:Jp2Image:printStructure (bsc#1189330).

CVE-2021-32617: Fixed denial of service inside inefficient algorithm
 (quadratic complexity) (bsc#1186192).

CVE-2021-31292: Fixed integer overflow in CrwMap:encode0x1810
 (bsc#1188756).

CVE-2021-31291: Fixed heap-based buffer overflow vulnerability in
 jp2image.cpp may lead to a denial of service (bsc#1188733).

CVE-2021-29470: Fixed out-of-bounds read in
 Exiv2:Jp2Image:encodeJp2Header (bsc#1185447).

CVE-2020-18899: Fixed uncontrolled memory allocation (bsc#1189636).

CVE-2020-18898: Fixed remote denial of service in printIFDStructure
 function (bsc#1189780).

CVE-2018-8977: Fixed remote denial of service in
 Exiv2::Internal::printCsLensFFFF function in canonmn_int.cpp
 (bsc#1086798).

CVE-2018-8976: Fixed remote denial of service in image.cpp
 Exiv2::Internal::stringFormat via out-of-bounds read (bsc#1086810).

CVE-2018-5772: Fixed segmentation fault caused by uncontrolled recursion
 inthe Exiv2::Image::printIFDStructure (bsc#1076579).

CVE-2018-18915: Fixed an infinite loop in the
 Exiv2:Image:printIFDStructure function (bsc#1114690).

CVE-2018-10772: Fixed segmentation fault when the function
 Exiv2::tEXtToDataBuf() is finished (bsc#1092096).");

  script_tag(name:"affected", value:"'exiv2' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Module for Desktop Applications 15-SP3, SUSE Linux Enterprise Module for Desktop Applications 15-SP4, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~150000.6.16.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150000.6.16.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~150000.6.16.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~150000.6.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150000.6.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~150000.6.16.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~150000.6.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150000.6.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~150000.6.16.1", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~150000.6.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150000.6.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~150000.6.16.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~150000.6.16.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150000.6.16.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~150000.6.16.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~150000.6.16.1", rls:"SLES15.0SP2"))) {
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
