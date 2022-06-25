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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0349");
  script_cve_id("CVE-2015-7554", "CVE-2015-8668", "CVE-2016-3186", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3632", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5314", "CVE-2016-5315", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5321", "CVE-2016-5322", "CVE-2016-5323", "CVE-2016-5875", "CVE-2016-6223");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2016-0349)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0349");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0349.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17480");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/12/26/7");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2016-04/msg00064.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/14/4");
  script_xref(name:"URL", value:"http://lwn.net/Vulnerabilities/695692/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2016-07/msg00087.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2016-1546.html");
  script_xref(name:"URL", value:"http://lwn.net/Vulnerabilities/696207/");
  script_xref(name:"URL", value:"http://lwn.net/Vulnerabilities/698795/");
  script_xref(name:"URL", value:"http://lwn.net/Vulnerabilities/699684/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the MGASA-2016-0349 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The _TIFFVGetField function in tif_dir.c in libtiff 4.0.6 allows
attackers to cause a denial of service (invalid memory write and
crash) or possibly have unspecified other impact via crafted field
data in an extension tag in a TIFF image. (CVE-2015-7554)

Heap-based buffer overflow in the PackBitsPreEncode function in
tif_packbits.c in bmp2tiff in libtiff 4.0.6 and earlier allows remote
attackers to execute arbitrary code or cause a denial of service via a
large width field in a BMP image. (CVE-2015-8668)

Buffer overflow in the readextension function in gif2tiff.c in LibTIFF
4.0.6 allows remote attackers to cause a denial of service (application
crash) via a crafted GIF file. (CVE-2016-3186) (the program gif2tiff has
been obsoleted)

The fpAcc function in tif_predict.c in the tiff2rgba tool in LibTIFF 4.0.6
and earlier allows remote attackers to cause a denial of service
(divide-by-zero error) via a crafted TIFF image. (CVE-2016-3622)

The rgb2ycbcr tool in LibTIFF 4.0.6 and earlier allows remote attackers
to cause a denial of service (divide-by-zero) by setting the (1) v or (2)
h parameter to 0. (CVE-2016-3623)

The _TIFFVGetField function in tif_dirinfo.c in LibTIFF 4.0.6 and earlier
allows remote attackers to cause a denial of service (out-of-bounds write)
or execute arbitrary code via a crafted TIFF image. (CVE-2016-3632)

Multiple integer overflows in the (1) cvt_by_strip and (2) cvt_by_tile
functions in the tiff2rgba tool in LibTIFF 4.0.6 and earlier, when -b mode
is enabled,allow remote attackers to cause a denial of service (crash) or
execute arbitrary code via a crafted TIFF image, which triggers an
out-of-bounds write. (CVE-2016-3945)

Heap-based buffer overflow in the horizontalDifference8 function in
tif_pixarlog.c in LibTIFF 4.0.6 and earlier allows remote attackers
to cause a denial of service (crash) or execute arbitrary code via
a crafted TIFF image to tiffcp. (CVE-2016-3990)

Heap-based buffer overflow in the loadImage function in the tiffcrop tool
in LibTIFF 4.0.6 and earlier allows remote attackers to cause a denial of
service (out-of-bounds write) or execute arbitrary code via a crafted TIFF
image with zero tiles. (CVE-2016-3991)

PixarLogDecode() out-of-bound writes (CVE-2016-5314)

tif_dir.c: setByteArray() Read access violation (CVE-2016-5315)

tif_pixarlog.c: PixarLogCleanup() Segmentation fault (CVE-2016-5316)

crash occurs when generating a thumbnail for a crafted TIFF image
(CVE-2016-5317)

rgb2ycbcr: command execution (CVE-2016-5320)

DumpModeDecode(): Ddos (CVE-2016-5321)

tiffcrop: extractContigSamplesBytes: out-of-bounds read (CVE-2016-5322)

tiffcrop _TIFFFax3fillruns(): divide by zero (CVE-2016-5323)

tiff: heap-based buffer overflow when using the PixarLog compression format (CVE-2016-5875)

tiff: information leak in libtiff/tif_read.c (CVE-2016-6223)");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-devel", rpm:"lib64tiff-devel~4.0.6~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-static-devel", rpm:"lib64tiff-static-devel~4.0.6~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff5", rpm:"lib64tiff5~4.0.6~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.6~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.6~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~4.0.6~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static-devel", rpm:"libtiff-static-devel~4.0.6~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.6~1.4.mga5", rls:"MAGEIA5"))) {
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
