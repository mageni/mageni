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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2017.795");
  script_cve_id("CVE-2016-10092", "CVE-2016-10093", "CVE-2016-10271", "CVE-2016-10272", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3624", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9538", "CVE-2016-9540", "CVE-2017-5225");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DLA-795)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-795");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-795");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DLA-795 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Numerous security vulnerabilities have been found through fuzzing on various tiff-related binaries. Crafted TIFF images allows remote attacks to cause denial of service or, in certain cases arbitrary code execution through divide-by-zero, out of bunds write, integer and heap overflow.

CVE-2016-3622

The fpAcc function in tif_predict.c in the tiff2rgba tool in LibTIFF 4.0.6 and earlier allows remote attackers to cause a denial of service (divide-by-zero error) via a crafted TIFF image.

CVE-2016-3623

The rgb2ycbcr tool in LibTIFF 4.0.6 and earlier allows remote attackers to cause a denial of service (divide-by-zero) by setting the (1) v or (2) h parameter to 0. (Fixed along with CVE-2016-3624.)

CVE-2016-3624

The cvtClump function in the rgb2ycbcr tool in LibTIFF 4.0.6 and earlier allows remote attackers to cause a denial of service (out-of-bounds write) by setting the '-v' option to -1.

CVE-2016-3945

Multiple integer overflows in the (1) cvt_by_strip and (2) cvt_by_tile functions in the tiff2rgba tool in LibTIFF 4.0.6 and earlier, when -b mode is enabled, allow remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted TIFF image, which triggers an out-of-bounds write.

CVE-2016-3990

Heap-based buffer overflow in the horizontalDifference8 function in tif_pixarlog.c in LibTIFF 4.0.6 and earlier allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted TIFF image to tiffcp.

CVE-2016-9533

tif_pixarlog.c in libtiff 4.0.6 has out-of-bounds write vulnerabilities in heap allocated buffers. Reported as MSVR 35094, aka 'PixarLog horizontalDifference heap-buffer-overflow.'

CVE-2016-9534

tif_write.c in libtiff 4.0.6 has an issue in the error code path of TIFFFlushData1() that didn't reset the tif_rawcc and tif_rawcp members. Reported as MSVR 35095, aka 'TIFFFlushData1 heap-buffer-overflow.'

CVE-2016-9535

tif_predict.h and tif_predict.c in libtiff 4.0.6 have assertions that can lead to assertion failures in debug mode, or buffer overflows in release mode, when dealing with unusual tile size like YCbCr with subsampling. Reported as MSVR 35105, aka 'Predictor heap-buffer-overflow.'

CVE-2016-9536

tools/tiff2pdf.c in libtiff 4.0.6 has out-of-bounds write vulnerabilities in heap allocated buffers in t2p_process_jpeg_strip(). Reported as MSVR 35098, aka 't2p_process_jpeg_strip heap-buffer-overflow.'

CVE-2016-9537

tools/tiffcrop.c in libtiff 4.0.6 has out-of-bounds write vulnerabilities in buffers. Reported as MSVR 35093, MSVR 35096, and MSVR 35097.

CVE-2016-9538

tools/tiffcrop.c in libtiff 4.0.6 reads an undefined buffer in readContigStripsIntoBuffer() because of a uint16 integer overflow. Reported as MSVR 35100.

CVE-2016-9540

tools/tiffcp.c in libtiff 4.0.6 has an out-of-bounds write on tiled images with odd tile width versus image width. Reported as MSVR 35103, aka cpStripToTile ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.2-6+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.2-6+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.2-6+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5-alt-dev", ver:"4.0.2-6+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.0.2-6+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.2-6+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.2-6+deb7u9", rls:"DEB7"))) {
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
