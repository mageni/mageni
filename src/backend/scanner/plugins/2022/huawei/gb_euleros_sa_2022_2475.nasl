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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2475");
  script_cve_id("CVE-2020-11758", "CVE-2020-11759", "CVE-2020-11760", "CVE-2020-11761", "CVE-2020-11762", "CVE-2020-11763", "CVE-2020-11764", "CVE-2020-11765", "CVE-2020-15305", "CVE-2020-15306", "CVE-2021-20296", "CVE-2021-23215", "CVE-2021-26260", "CVE-2021-3474", "CVE-2021-3475", "CVE-2021-3476", "CVE-2021-3477", "CVE-2021-3478", "CVE-2021-3479", "CVE-2021-3598", "CVE-2021-3605", "CVE-2021-3933");
  script_tag(name:"creation_date", value:"2022-10-10 07:55:28 +0000 (Mon, 10 Oct 2022)");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 12:55:00 +0000 (Tue, 05 Apr 2022)");

  script_name("Huawei EulerOS: Security Advisory for OpenEXR (EulerOS-SA-2022-2475)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2475");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2475");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'OpenEXR' package(s) announced via the EulerOS-SA-2022-2475 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in OpenEXR before 2.4.1. There is an std::vector out-of-bounds read and write, as demonstrated by ImfTileOffsets.cpp.(CVE-2020-11763)

An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds read during Huffman uncompression, as demonstrated by FastHufDecoder::refill in ImfFastHuf.cpp.(CVE-2020-11761)

An issue was discovered in OpenEXR before 2.4.1. There is an off-by-one error in use of the ImfXdr.h read function by DwaCompressor::Classifier::Classifier, leading to an out-of-bounds read.(CVE-2020-11765)

An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds read and write in DwaCompressor::uncompress in ImfDwaCompressor.cpp when handling the UNKNOWN compression case.(CVE-2020-11762)

An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds read during RLE uncompression in rleUncompress in ImfRle.cpp.(CVE-2020-11760)

An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds read in ImfOptimizedPixelReading.h.(CVE-2020-11758)

An issue was discovered in OpenEXR before 2.4.1. Because of integer overflows in CompositeDeepScanLine::Data::handleDeepFrameBuffer and readSampleCountForLineBlock, an attacker can write to an out-of-bounds pointer.(CVE-2020-11759)

An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds write in copyIntoFrameBuffer in ImfMisc.cpp.(CVE-2020-11764)

There's a flaw in OpenEXR's rleUncompress functionality in versions prior to 3.0.5. An attacker who is able to submit a crafted file to an application linked with OpenEXR could cause an out-of-bounds read. The greatest risk from this flaw is to application availability.(CVE-2021-3605)

There's a flaw in OpenEXR's ImfDeepScanLineInputFile functionality in versions prior to 3.0.5. An attacker who is able to submit a crafted file to an application linked with OpenEXR could cause an out-of-bounds read. The greatest risk from this flaw is to application availability.(CVE-2021-3598)

An integer overflow leading to a heap-buffer overflow was found in the DwaCompressor of OpenEXR in versions before 3.0.1. An attacker could use this flaw to crash an application compiled with OpenEXR.(CVE-2021-23215)

There's a flaw in OpenEXR's Scanline API functionality in versions before 3.0.0-beta. An attacker who is able to submit a crafted file to be processed by OpenEXR could trigger excessive consumption of memory, resulting in an impact to system availability.(CVE-2021-3479)

There's a flaw in OpenEXR's scanline input file functionality in versions before 3.0.0-beta. An attacker able to submit a crafted file to be processed by OpenEXR could consume excessive system memory. The greatest impact of this flaw is to system availability.(CVE-2021-3478)

A flaw was found in OpenEXR's B44 uncompression functionality in versions before 3.0.0-beta. An attacker who is able to submit a crafted file to OpenEXR could ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'OpenEXR' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"OpenEXR-libs", rpm:"OpenEXR-libs~2.2.0~15.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
