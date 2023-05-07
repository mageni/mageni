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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0151");
  script_cve_id("CVE-2022-36354", "CVE-2022-38143", "CVE-2022-41639", "CVE-2022-41684", "CVE-2022-41794", "CVE-2022-41838", "CVE-2022-41977", "CVE-2022-41981", "CVE-2022-41988", "CVE-2022-41999", "CVE-2022-43592", "CVE-2022-43593", "CVE-2022-43594", "CVE-2022-43595", "CVE-2022-43596", "CVE-2022-43597", "CVE-2022-43598", "CVE-2022-43599", "CVE-2022-43600", "CVE-2022-43601", "CVE-2022-43602", "CVE-2022-43603", "CVE-2023-22845", "CVE-2023-24472", "CVE-2023-24473");
  script_tag(name:"creation_date", value:"2023-04-24 04:13:19 +0000 (Mon, 24 Apr 2023)");
  script_version("2023-04-24T10:19:26+0000");
  script_tag(name:"last_modification", value:"2023-04-24 10:19:26 +0000 (Mon, 24 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-30 01:37:00 +0000 (Fri, 30 Dec 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0151");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0151.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31364");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/T3LET4MEPBSBJZK4EMLEBY4FUXKU5BMN/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/MLUXEL7AB2S5ACSDCHG67GEZHUYZBR5O/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/LK6TY36VQ3FQXMZ2VXHZGQ43VDLD67GG/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3382");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5384");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openimageio' package(s) announced via the MGASA-2023-0151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap out-of-bounds read vulnerability exists in the RLA format parser of
OpenImageIO master-branch-9aeece7a and v2.3.19.0. More specifically, in
the way run-length encoded byte spans are handled. A malformed RLA file
can lead to an out-of-bounds read of heap metadata which can result in
sensitive information leak. (CVE-2022-36354)

A heap out-of-bounds write vulnerability exists in the way OpenImageIO
v2.3.19.0 processes RLE encoded BMP images. A specially-crafted bmp file
can write to arbitrary out of bounds memory, which can lead to arbitrary
code execution. (CVE-2022-38143)

A heap based buffer overflow vulnerability exists in tile decoding code of
TIFF image parser in OpenImageIO master-branch-9aeece7a and v2.3.19.0. A
specially-crafted TIFF file can lead to an out of bounds memory
corruption, which can result in arbitrary code execution.
(CVE-2022-41639)

A heap out of bounds read vulnerability exists in the OpenImageIO
master-branch-9aeece7a when parsing the image file directory part of a PSD
image file. A specially-crafted .psd file can cause a read of arbitrary
memory address which can lead to denial of service. (CVE-2022-41684)

A heap based buffer overflow vulnerability exists in the PSD thumbnail
resource parsing code of OpenImageIO 2.3.19.0. A specially-crafted PSD
file can lead to arbitrary code execution. (CVE-2022-41794)

A code execution vulnerability exists in the DDS scanline parsing
functionality of OpenImageIO Project OpenImageIO v2.4.4.2. A
specially-crafted .dds can lead to a heap buffer overflow.
(CVE-2022-41838)

An out of bounds read vulnerability exists in the way OpenImageIO version
v2.3.19.0 processes string fields in TIFF image files. A specially-crafted
TIFF file can lead to information disclosure. (CVE-2022-41977)

A stack-based buffer overflow vulnerability exists in the TGA file format
parser of OpenImageIO v2.3.19.0. A specially-crafted targa file can lead
to out of bounds read and write on the process stack, which can lead to
arbitrary code execution. (CVE-2022-41981)

An information disclosure vulnerability exists in the
OpenImageIO::decode_iptc_iim() functionality of OpenImageIO Project
OpenImageIO v2.3.19.0. A specially-crafted TIFF file can lead to a
disclosure of sensitive information. (CVE-2022-41988)

A denial of service vulnerability exists in the DDS native tile reading
functionality of OpenImageIO Project OpenImageIO v2.3.19.0 and v2.4.4.2. A
specially-crafted .dds can lead to denial of service. (CVE-2022-41999)

An information disclosure vulnerability exists in the DPXOutput::close()
functionality of OpenImageIO Project OpenImageIO v2.4.4.2. A specially
crafted ImageOutput Object can lead to leaked heap data. (CVE-2022-43592)

A denial of service vulnerability exists in the DPXOutput::close()
functionality of OpenImageIO Project OpenImageIO v2.4.4.2. A specially
crafted ImageOutput Object can lead to null pointer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openimageio' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64openimageio-devel", rpm:"lib64openimageio-devel~2.2.10.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openimageio2.2", rpm:"lib64openimageio2.2~2.2.10.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenimageio-devel", rpm:"libopenimageio-devel~2.2.10.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenimageio2.2", rpm:"libopenimageio2.2~2.2.10.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openimageio", rpm:"openimageio~2.2.10.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openimageio", rpm:"python3-openimageio~2.2.10.0~1.1.mga8", rls:"MAGEIA8"))) {
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
