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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0391");
  script_cve_id("CVE-2017-11336", "CVE-2017-11337", "CVE-2017-11338", "CVE-2017-11339", "CVE-2017-11340", "CVE-2017-11553", "CVE-2017-11591", "CVE-2017-11592", "CVE-2017-11683", "CVE-2017-12955", "CVE-2017-12956", "CVE-2017-12957", "CVE-2017-14857", "CVE-2017-14859", "CVE-2017-14860", "CVE-2017-14862", "CVE-2017-14864");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-22 14:50:00 +0000 (Tue, 22 Aug 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0391)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0391");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0391.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21158");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21922");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/06/30/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2, exiv2' package(s) announced via the MGASA-2017-0391 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Opening an image created on certain pentax cameras with gwenview, which
uses the exiv2 library, causes gwenview to segfault. Exiv2 upstream
created a patch to resolve this problem (bugfix - applies only to mga6).

The following security issues were also fixed:
*Heap overflow in Exiv2::Image::printIFDStructure (CVE-2017-11336)
*Invalid free in the Action::TaskFactory::cleanup function
(CVE-2017-11337)
*Infinite loop in the Exiv2::Image::printIFDStructure function of
image.cpp (CVE-2017-11338)
*Heap-based buffer overflow in the Image::printIFDStructure function of
image.cpp (CVE-2017-11339)
*Segmentation fault in the XmpParser::terminate() function
(CVE-2017-11340)
*Illegal address access in the extend_alias_table function in
localealias.c (CVE-2017-11553)
*Floating point exception in the Exiv2::ValueType function
(CVE-2017-11591)
*Alloc-dealloc-mismatch in Exiv2::FileIo::seek (CVE-2017-11592)
*Reachable assertion in the Internal::TiffReader::visitDirectory
function in tiffvisitor.cpp (CVE-2017-11683)
*Heap-based buffer overflow in basicio.cpp (CVE-2017-12955)
*Illegal address access in Exiv2::FileIo::path[abi:cxx11]() in
basicio.cpp (CVE-2017-12956)
*Heap-based buffer over-read in the Exiv2::Image::io function in
image.cpp (CVE-2017-12957)
*Bad free in Exiv2::Image::~Image (CVE-2017-14857)
*Invalid memory address dereference in Exiv2::DataValue::read
(CVE-2017-14859)
*Heap-buffer-overflow in Exiv2::Jp2Image::readMetadata (CVE-2017-14860)
*Invalid memory address dereference in Exiv2::StringValueBase::read
(CVE-2017-14862)
*Invalid memory address dereference in Exiv2::getULong (CVE-2017-14864)");

  script_tag(name:"affected", value:"'exiv2, exiv2' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.24~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-doc", rpm:"exiv2-doc~0.24~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2-devel", rpm:"lib64exiv2-devel~0.24~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2_13", rpm:"lib64exiv2_13~0.24~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.24~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2_13", rpm:"libexiv2_13~0.24~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.26~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-doc", rpm:"exiv2-doc~0.26~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2-devel", rpm:"lib64exiv2-devel~0.26~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2_26", rpm:"lib64exiv2_26~0.26~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2_26", rpm:"libexiv2_26~0.26~2.2.mga6", rls:"MAGEIA6"))) {
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
