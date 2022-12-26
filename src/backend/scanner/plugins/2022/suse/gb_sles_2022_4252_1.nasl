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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4252.1");
  script_cve_id("CVE-2018-20097", "CVE-2019-13112", "CVE-2021-29457", "CVE-2021-29473", "CVE-2021-31291", "CVE-2021-32815", "CVE-2021-34334", "CVE-2021-37620");
  script_tag(name:"creation_date", value:"2022-11-29 04:18:38 +0000 (Tue, 29 Nov 2022)");
  script_version("2022-11-29T10:12:26+0000");
  script_tag(name:"last_modification", value:"2022-11-29 10:12:26 +0000 (Tue, 29 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 18:55:00 +0000 (Wed, 02 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4252-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4252-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224252-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the SUSE-SU-2022:4252-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exiv2 fixes the following issues:

CVE-2019-13112: Fixed an uncontrolled memory allocation in
 PngChunk:parseChunkContent causing denial of service. (bsc#1142681)

CVE-2021-37620: Fixed out-of-bounds read in XmpTextValue:read().
 (bsc#1189332)

CVE-2021-34334: Fixed a DoS due to integer overflow in loop counter.
 (bsc#1189338)

CVE-2021-31291: Fixed a heap-based buffer overflow vulnerability in
 jp2image.cpp may lead to a denial of service via crafted metadata
 (bsc#1188733).

CVE-2021-32815: Fixed a deny-of-service due to assertion failure in
 crwimage_int.cpp (bsc#1189337).

CVE-2018-20097: Fixed SEGV in
 Exiv2::Internal::TiffParserWorker::findPrimaryGroupsu (bsc#1119562).

CVE-2021-29457: Fixed a heap buffer overflow when write metadata into a
 crafted image file (bsc#1185002).

CVE-2021-29473: Fixed out-of-bounds read in
 Exiv2::Jp2Image:doWriteMetadata (bsc#1186231).");

  script_tag(name:"affected", value:"'exiv2' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.23~12.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.23~12.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12", rpm:"libexiv2-12~0.23~12.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12-debuginfo", rpm:"libexiv2-12-debuginfo~0.23~12.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.23~12.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.23~12.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12", rpm:"libexiv2-12~0.23~12.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12-debuginfo", rpm:"libexiv2-12-debuginfo~0.23~12.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.23~12.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.23~12.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12", rpm:"libexiv2-12~0.23~12.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12-debuginfo", rpm:"libexiv2-12-debuginfo~0.23~12.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.23~12.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.23~12.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12", rpm:"libexiv2-12~0.23~12.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12-debuginfo", rpm:"libexiv2-12-debuginfo~0.23~12.18.1", rls:"SLES12.0SP5"))) {
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
