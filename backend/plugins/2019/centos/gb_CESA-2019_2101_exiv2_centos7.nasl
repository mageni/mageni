# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883101");
  script_version("2019-09-20T05:25:28+0000");
  script_cve_id("CVE-2017-17724", "CVE-2018-8976", "CVE-2018-8977", "CVE-2018-9305", "CVE-2018-10772", "CVE-2018-10958", "CVE-2018-10998", "CVE-2018-11037", "CVE-2018-12264", "CVE-2018-12265", "CVE-2018-14046", "CVE-2018-17282", "CVE-2018-17581", "CVE-2018-18915", "CVE-2018-19107", "CVE-2018-19108", "CVE-2018-19535", "CVE-2018-19607", "CVE-2018-20096", "CVE-2018-20097", "CVE-2018-20098", "CVE-2018-20099");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-20 05:25:28 +0000 (Fri, 20 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-19 02:01:15 +0000 (Thu, 19 Sep 2019)");
  script_name("CentOS Update for exiv2 CESA-2019:2101 centos7 ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-September/023446.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2'
  package(s) announced via the CESA-2019:2101 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The exiv2 packages provide a command line utility which can display and
manipulate image metadata such as EXIF, LPTC, and JPEG comments.

The following packages have been upgraded to a later upstream version:
exiv2 (0.27.0). (BZ#1652637)

Security Fix(es):

  * exiv2: heap-buffer-overflow in Exiv2::IptcData::printStructure in
src/iptc.cpp (CVE-2017-17724)

  * exiv2: out-of-bounds read in Exiv2::Internal::stringFormat image.cpp
(CVE-2018-8976)

  * exiv2: invalid memory access in Exiv2::Internal::printCsLensFFFF function
in canonmn_int.cpp (CVE-2018-8977)

  * exiv2: out of bounds read in IptcData::printStructure in iptc.c
(CVE-2018-9305)

  * exiv2: OOB read in pngimage.cpp:tEXtToDataBuf() allows for crash via
crafted file (CVE-2018-10772)

  * exiv2: SIGABRT caused by memory allocation in
types.cpp:Exiv2::Internal::PngChunk::zlibUncompress() (CVE-2018-10958)

  * exiv2: SIGABRT by triggering an incorrect Safe::add call (CVE-2018-10998)

  * exiv2: information leak via a crafted file (CVE-2018-11037)

  * exiv2: integer overflow in getData function in preview.cpp
(CVE-2018-12264)

  * exiv2: integer overflow in the LoaderExifJpeg class in preview.cpp
(CVE-2018-12265)

  * exiv2: heap-based buffer over-read in WebPImage::decodeChunks in
webpimage.cpp (CVE-2018-14046)

  * exiv2: NULL pointer dereference in Exiv2::DataValue::copy in value.cpp
leading to application crash (CVE-2018-17282)

  * exiv2: Stack overflow in CiffDirectory::readDirectory() at
crwimage_int.cpp leading to denial of service (CVE-2018-17581)

  * exiv2: infinite loop in Exiv2::Image::printIFDStructure function in
image.cpp (CVE-2018-18915)

  * exiv2: heap-based buffer over-read in Exiv2::IptcParser::decode in
iptc.cpp (CVE-2018-19107)

  * exiv2: infinite loop in Exiv2::PsdImage::readMetadata in psdimage.cpp
(CVE-2018-19108)

  * exiv2: heap-based buffer over-read in PngChunk::readRawProfile in
pngchunk_int.cpp (CVE-2018-19535)

  * exiv2: NULL pointer dereference in Exiv2::isoSpeed in easyaccess.cpp
(CVE-2018-19607)

  * exiv2: Heap-based buffer over-read in Exiv2::tEXtToDataBuf function
resulting in a denial of service (CVE-2018-20096)

  * exiv2: Segmentation fault in
Exiv2::Internal::TiffParserWorker::findPrimaryGroups function
(CVE-2018-20097)

  * exiv2: Heap-based buffer over-read in Exiv2::Jp2Image::encodeJp2Header
resulting in a denial of service (CVE-2018-20098)

  * exiv2: Infinite loop in Exiv2::Jp2Image::encodeJp2Header resulting in a
denial of service (CVE-2018-20099)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section.");

  script_tag(name:"affected", value:"'exiv2' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.27.0~2.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-devel", rpm:"exiv2-devel~0.27.0~2.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-doc", rpm:"exiv2-doc~0.27.0~2.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-libs", rpm:"exiv2-libs~0.27.0~2.el7_6", rls:"CentOS7"))) {
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
