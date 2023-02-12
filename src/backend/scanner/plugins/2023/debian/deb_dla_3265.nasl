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
  script_oid("1.3.6.1.4.1.25623.1.0.893265");
  script_version("2023-01-12T10:12:15+0000");
  script_cve_id("CVE-2017-11591", "CVE-2017-14859", "CVE-2017-14862", "CVE-2017-14864", "CVE-2017-17669", "CVE-2017-18005", "CVE-2018-17581", "CVE-2018-19107", "CVE-2018-19108", "CVE-2018-19535", "CVE-2018-20097", "CVE-2018-8976", "CVE-2019-13110", "CVE-2019-13112", "CVE-2019-13114", "CVE-2019-13504", "CVE-2019-14369", "CVE-2019-14370", "CVE-2019-17402", "CVE-2020-18771", "CVE-2021-29458", "CVE-2021-32815", "CVE-2021-34334", "CVE-2021-37620", "CVE-2021-37621", "CVE-2021-37622");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-30 16:12:00 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"creation_date", value:"2023-01-11 02:00:22 +0000 (Wed, 11 Jan 2023)");
  script_name("Debian LTS: Security Advisory for exiv2 (DLA-3265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00004.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3265-1");
  script_xref(name:"Advisory-ID", value:"DLA-3265-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/876893");
  script_xref(name:"URL", value:"https://bugs.debian.org/885981");
  script_xref(name:"URL", value:"https://bugs.debian.org/886006");
  script_xref(name:"URL", value:"https://bugs.debian.org/903813");
  script_xref(name:"URL", value:"https://bugs.debian.org/910060");
  script_xref(name:"URL", value:"https://bugs.debian.org/913272");
  script_xref(name:"URL", value:"https://bugs.debian.org/913273");
  script_xref(name:"URL", value:"https://bugs.debian.org/915135");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2'
  package(s) announced via the DLA-3265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a number of memory access violations and other input
validation failures that can be triggered by passing specially crafted files to
exiv2.

CVE-2017-11591

There is a Floating point exception in the Exiv2::ValueType function that
will lead to a remote denial of service attack via crafted input.

CVE-2017-14859

An Invalid memory address dereference was discovered in
Exiv2::StringValueBase::read in value.cpp. The vulnerability causes a
segmentation fault and application crash, which leads to denial of service.

CVE-2017-14862

An Invalid memory address dereference was discovered in
Exiv2::DataValue::read in value.cpp. The vulnerability causes a
segmentation fault and application crash, which leads to denial of service.

CVE-2017-14864

An Invalid memory address dereference was discovered in Exiv2::getULong in
types.cpp. The vulnerability causes a segmentation fault and application
crash, which leads to denial of service.

CVE-2017-17669

There is a heap-based buffer over-read in the
Exiv2::Internal::PngChunk::keyTXTChunk function of pngchunk_int.cpp. A
crafted PNG file will lead to a remote denial of service attack.

CVE-2017-18005

Exiv2 has a Null Pointer Dereference in the Exiv2::DataValue::toLong
function in value.cpp, related to crafted metadata in a TIFF file.

CVE-2018-8976

jpgimage.cpp allows remote attackers to cause a denial of service
(image.cpp Exiv2::Internal::stringFormat out-of-bounds read) via a crafted
file.

CVE-2018-17581

CiffDirectory::readDirectory() at crwimage_int.cpp has excessive stack
consumption due to a recursive function, leading to Denial of service.

CVE-2018-19107

Exiv2::IptcParser::decode in iptc.cpp (called from psdimage.cpp in the PSD
image reader) may suffer from a denial of service (heap-based buffer
over-read) caused by an integer overflow via a crafted PSD image file.

CVE-2018-19108

Exiv2::PsdImage::readMetadata in psdimage.cpp in the PSD image reader may
suffer from a denial of service (infinite loop) caused by an integer
overflow via a crafted PSD image file.

CVE-2018-19535

PngChunk::readRawProfile in pngchunk_int.cpp may cause a denial of service
(application crash due to a heap-based buffer over-read) via a crafted PNG
file.

CVE-2018-20097

There is a SEGV in Exiv2::Internal::TiffParserWorker::findPrimaryGroups of
tiffimage_int.cpp. A crafted input will lead to a remote denial of service
attack.

CVE-2019-13110

A CiffDirectory::readDirectory integer overflow and out-of-bounds read
allows an attacker to cause a denial of service (SIGSEGV) via a crafted CRW
image file.

CVE-2019-13112

A PngChunk::parseChunkContent uncontrolled memory allocation  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'exiv2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
0.25-4+deb10u4.

We recommend that you upgrade your exiv2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.25-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libexiv2-14", ver:"0.25-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libexiv2-dev", ver:"0.25-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libexiv2-doc", ver:"0.25-4+deb10u4", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
