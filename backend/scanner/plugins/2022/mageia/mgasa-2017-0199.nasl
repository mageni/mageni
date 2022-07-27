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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0199");
  script_cve_id("CVE-2014-8128", "CVE-2016-10092", "CVE-2016-10093", "CVE-2016-10094", "CVE-2016-10095", "CVE-2016-10266", "CVE-2016-10267", "CVE-2016-10268", "CVE-2016-10269", "CVE-2016-10270", "CVE-2016-10271", "CVE-2016-10272", "CVE-2016-3658", "CVE-2016-9535", "CVE-2017-5225", "CVE-2017-7592", "CVE-2017-7593", "CVE-2017-7594", "CVE-2017-7595", "CVE-2017-7596", "CVE-2017-7597", "CVE-2017-7598", "CVE-2017-7599", "CVE-2017-7600", "CVE-2017-7601", "CVE-2017-7602");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0199)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0199");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0199.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20057");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the MGASA-2017-0199 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap-based buffer overflow in the readContigStripsIntoBuffer function in
tif_unix.c in LibTIFF 4.0.7 allows remote attackers to have unspecified
impact via a crafted image. (CVE-2016-10092)

Integer overflow in tools/tiffcp.c in LibTIFF 4.0.7 allows remote
attackers to have unspecified impact via a crafted image, which triggers a
heap-based buffer overflow. (CVE-2016-10093)

Off-by-one error in the t2p_readwrite_pdf_image_tile function in
tools/tiff2pdf.c in LibTIFF 4.0.7 allows remote attackers to have
unspecified impact via a crafted image. (CVE-2016-10094)

Stack-based buffer overflow in the _TIFFVGetField function in tif_dir.c in
LibTIFF 4.0.7 allows remote attackers to cause a denial of service (crash)
via a crafted TIFF file. (CVE-2016-10095)

LibTIFF version 4.0.7 is vulnerable to a heap buffer overflow in the
tools/tiffcp resulting in DoS or code execution via a crafted
BitsPerSample value. (CVE-2017-5225)

LibTIFF 4.0.7 allows remote attackers to cause a denial of service
(divide-by-zero error and application crash) via a crafted TIFF image,
related to libtiff/tif_read.c:351:22. (CVE-2016-10266)

LibTIFF 4.0.7 allows remote attackers to cause a denial of service
(divide-by-zero error and application crash) via a crafted TIFF image,
related to libtiff/tif_ojpeg.c:816:8. (CVE-2016-10267)

tools/tiffcp.c in LibTIFF 4.0.7 allows remote attackers to cause a denial
of service (integer underflow and heap-based buffer under-read) or
possibly have unspecified other impact via a crafted TIFF image, related
to 'READ of size 78490' and libtiff/tif_unix.c:115:23. (CVE-2016-10268)

LibTIFF 4.0.7 allows remote attackers to cause a denial of service
(heap-based buffer over-read) or possibly have unspecified other impact
via a crafted TIFF image, related to 'READ of size 512' and
libtiff/tif_unix.c:340:2. (CVE-2016-10269)

LibTIFF 4.0.7 allows remote attackers to cause a denial of service
(heap-based buffer over-read) or possibly have unspecified other impact
via a crafted TIFF image, related to 'READ of size 8' and
libtiff/tif_read.c:523:22. (CVE-2016-10270)

tools/tiffcrop.c in LibTIFF 4.0.7 allows remote attackers to cause a
denial of service (heap-based buffer over-read and buffer overflow) or
possibly have unspecified other impact via a crafted TIFF image, related
to 'READ of size 1' and libtiff/tif_fax3.c:413:13. (CVE-2016-10271)

LibTIFF 4.0.7 allows remote attackers to cause a denial of service
(heap-based buffer overflow) or possibly have unspecified other impact via
a crafted TIFF image, related to 'WRITE of size 2048' and
libtiff/tif_next.c:64:9. (CVE-2016-10272)

The putagreytile function in tif_getimage.c in LibTIFF 4.0.7 has a
left-shift undefined behavior issue, which might allow remote attackers to
cause a denial of service (application crash) or possibly have unspecified
other impact via a crafted image. (CVE-2017-7592)

tif_read.c in LibTIFF 4.0.7 does not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libtiff' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-devel", rpm:"lib64tiff-devel~4.0.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-static-devel", rpm:"lib64tiff-static-devel~4.0.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff5", rpm:"lib64tiff5~4.0.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~4.0.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static-devel", rpm:"libtiff-static-devel~4.0.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.8~1.mga5", rls:"MAGEIA5"))) {
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
