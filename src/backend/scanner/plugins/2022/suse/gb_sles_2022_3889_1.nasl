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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3889.1");
  script_cve_id("CVE-2017-1000128", "CVE-2019-13108", "CVE-2019-13111", "CVE-2020-19716", "CVE-2021-29457", "CVE-2021-29463", "CVE-2021-29470", "CVE-2021-29623", "CVE-2021-31291", "CVE-2021-32617", "CVE-2021-34334", "CVE-2021-37620", "CVE-2021-37621", "CVE-2021-37622", "CVE-2021-37623");
  script_tag(name:"creation_date", value:"2022-11-08 04:34:47 +0000 (Tue, 08 Nov 2022)");
  script_version("2022-11-08T10:12:11+0000");
  script_tag(name:"last_modification", value:"2022-11-08 10:12:11 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 18:55:00 +0000 (Wed, 02 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3889-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3889-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223889-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the SUSE-SU-2022:3889-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exiv2 fixes the following issues:

Updated to version 0.27.5 (jsc#PED-1393):

CVE-2017-1000128: Fixed stack out of bounds read in JPEG2000 parser
 (bsc#1068871).

CVE-2019-13108: Fixed integer overflow PngImage:readMetadata
 (bsc#1142675).

CVE-2020-19716: Fixed buffer overflow vulnerability in the Databuf
 function in types.cpp (bsc#1188645).

CVE-2021-29457: Fixed heap buffer overflow when write metadata into a
 crafted image file (bsc#1185002).

CVE-2021-29470: Fixed out-of-bounds read in
 Exiv2:Jp2Image:encodeJp2Header (bsc#1185447).

CVE-2021-29623: Fixed read of uninitialized memory (bsc#1186053).

CVE-2021-31291: Fixed heap-based buffer overflow in jp2image.cpp
 (bsc#1188733).

CVE-2021-32617: Fixed denial of service due to inefficient algorithm
 (bsc#1186192).

CVE-2021-37620: Fixed out-of-bounds read in XmpTextValue:read()
 (bsc#1189332).

CVE-2021-37621: Fixed DoS due to infinite loop in
 Image:printIFDStructure (bsc#1189333).

CVE-2021-37622: Fixed DoS due to infinite loop in
 JpegBase:printStructure (bsc#1189334)

CVE-2021-34334: Fixed DoS due to integer overflow in loop
 counter(bsc#1189338)

CVE-2021-37623: Fixed DoS due to infinite loop in
 JpegBase:printStructure (bsc#1189335)

CVE-2021-29463: Fixed out-of-bounds read in webpimage.cpp (bsc#1185913).

CVE-2021-34334: Fixed DoS due to integer overflow in loop counter
 (bsc#1189338)

CVE-2019-13111: Fixed integer overflow in WebPImage:decodeChunks that
 lead to denial of service (bsc#1142679)

CVE-2021-29463: Fixed an out-of-bounds read was found in webpimage.cpp
 (bsc#1185913)

Bugfixes:

Fixed build using GCC 11 (bsc#1185218).

A new libexiv2-2_27 shared library is shipped, the libexiv2-2_26 is provided only for compatibility now.

Please recompile your applications using the exiv2 library.");

  script_tag(name:"affected", value:"'exiv2' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.27.5~150400.15.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.27.5~150400.15.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150400.9.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~150400.9.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-27", rpm:"libexiv2-27~0.27.5~150400.15.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-27-debuginfo", rpm:"libexiv2-27-debuginfo~0.27.5~150400.15.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.27.5~150400.15.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-xmp-static", rpm:"libexiv2-xmp-static~0.27.5~150400.15.4.1", rls:"SLES15.0SP4"))) {
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
