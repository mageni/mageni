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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0464");
  script_cve_id("CVE-2014-5271", "CVE-2014-5272", "CVE-2014-8541", "CVE-2014-8542", "CVE-2014-8543", "CVE-2014-8544", "CVE-2014-8545", "CVE-2014-8546", "CVE-2014-8547", "CVE-2014-8548");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:01:00 +0000 (Sat, 03 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2014-0464)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0464");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0464.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14042");
  script_xref(name:"URL", value:"http://git.videolan.org/?p=ffmpeg.git;a=log;h=n2.0.6");
  script_xref(name:"URL", value:"http://ffmpeg.org/olddownload.html");
  script_xref(name:"URL", value:"http://ffmpeg.org/security.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/08/16/6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg, ffmpeg' package(s) announced via the MGASA-2014-0464 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow in the encode_slice function in
libavcodec/proresenc_kostya.c in FFmpeg before 2.0.6 can cause a crash,
allowing a malicious image file to cause a denial of service (CVE-2014-5271).

libavcodec/iff.c in FFmpeg before 2.0.6 allows an attacker to have an
unspecified impact via a crafted iff image, which triggers an out-of-bounds
array access, related to the rgb8 and rgbn formats (CVE-2014-5272).

libavcodec/mjpegdec.c in FFmpeg before 2.0.6 considers only dimension
differences, and not bits-per-pixel differences, when determining whether an
image size has changed, which allows remote attackers to cause a denial of
service (out-of-bounds access) or possibly have unspecified other impact via
crafted MJPEG data (CVE-2014-8541).

libavcodec/utils.c in FFmpeg before 2.0.6 omits a certain codec ID during
enforcement of alignment, which allows remote attackers to cause a denial of
service (out-of-bounds access) or possibly have unspecified other impact via
crafted JV data (CVE-2014-8542).

libavcodec/mmvideo.c in FFmpeg before 2.0.6 does not consider all lines of
HHV Intra blocks during validation of image height, which allows remote
attackers to cause a denial of service (out-of-bounds access) or possibly
have unspecified other impact via crafted MM video data (CVE-2014-8543).

libavcodec/tiff.c in FFmpeg before 2.0.6 does not properly validate
bits-per-pixel fields, which allows remote attackers to cause a denial of
service (out-of-bounds access) or possibly have unspecified other impact via
crafted TIFF data (CVE-2014-8544).

libavcodec/pngdec.c in FFmpeg before 2.0.6 accepts the monochrome-black
format without verifying that the bits-per-pixel value is 1, which allows
remote attackers to cause a denial of service (out-of-bounds access) or
possibly have unspecified other impact via crafted PNG data (CVE-2014-8545).

Integer underflow in libavcodec/cinepak.c in FFmpeg before 2.0.6 allows
remote attackers to cause a denial of service (out-of-bounds access) or
possibly have unspecified other impact via crafted Cinepak video data
(CVE-2014-8546).

libavcodec/gifdec.c in FFmpeg before 2.0.6 does not properly compute image
heights, which allows remote attackers to cause a denial of service
(out-of-bounds access) or possibly have unspecified other impact via crafted
GIF data (CVE-2014-8547).

Off-by-one error in libavcodec/smc.c in FFmpeg before 2.0.6 allows remote
attackers to cause a denial of service (out-of-bounds access) or possibly
have unspecified other impact via crafted Quicktime Graphics (aka SMC) video
data (CVE-2014-8548).");

  script_tag(name:"affected", value:"'ffmpeg, ffmpeg' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec55", rpm:"lib64avcodec55~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec55", rpm:"lib64avcodec55~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter3", rpm:"lib64avfilter3~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter3", rpm:"lib64avfilter3~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat55", rpm:"lib64avformat55~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat55", rpm:"lib64avformat55~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil52", rpm:"lib64avutil52~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil52", rpm:"lib64avutil52~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc52", rpm:"lib64postproc52~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc52", rpm:"lib64postproc52~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample0", rpm:"lib64swresample0~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample0", rpm:"lib64swresample0~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler2", rpm:"lib64swscaler2~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler2", rpm:"lib64swscaler2~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec55", rpm:"libavcodec55~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec55", rpm:"libavcodec55~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter3", rpm:"libavfilter3~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter3", rpm:"libavfilter3~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat55", rpm:"libavformat55~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat55", rpm:"libavformat55~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil52", rpm:"libavutil52~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil52", rpm:"libavutil52~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc52", rpm:"libpostproc52~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc52", rpm:"libpostproc52~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample0", rpm:"libswresample0~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample0", rpm:"libswresample0~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler2", rpm:"libswscaler2~2.0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler2", rpm:"libswscaler2~2.0.6~1.mga4.tainted", rls:"MAGEIA4"))) {
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
