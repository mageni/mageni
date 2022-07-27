# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852988");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2017-17555", "CVE-2018-13305", "CVE-2019-11338", "CVE-2019-11339", "CVE-2019-15942");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-14 04:01:32 +0000 (Tue, 14 Jan 2020)");
  script_name("openSUSE Update for ffmpeg-4 openSUSE-SU-2020:0024-1 (ffmpeg-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00014.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg-4'
  package(s) announced via the openSUSE-SU-2020:0024_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg-4 fixes the following issues:

  ffmpeg-4 was updated to version 4.0.5, fixes boo#1133153

  - CVE-2019-11339: The studio profile decoder in libavcodec/mpeg4videodec.c
  in FFmpeg 4.0 allowed remote attackers to cause a denial of service
  (out-of-array access) or possibly have unspecified. (bsc#1133153)

  - For other changes see /usr/share/doc/packages/libavcodec58/Changelog

  Update to version 4.2.1:

  * Stable bug fix release, mainly codecs and format fixes.

  - CVE-2019-15942: Conditional jump or move depends on uninitialised value'
  issue in h2645_parse (boo#1149839)

  Update to FFmpeg 4.2 'Ada'

  * tpad filter

  * AV1 decoding support through libdav1d

  * dedot filter

  * chromashift and rgbashift filters

  * freezedetect filter

  * truehd_core bitstream filter

  * dhav demuxer

  * PCM-DVD encoder

  * GIF parser

  * vividas demuxer

  * hymt decoder

  * anlmdn filter

  * maskfun filter

  * hcom demuxer and decoder

  * ARBC decoder

  * libaribb24 based ARIB STD-B24 caption support (profiles A and C)

  * Support decoding of HEVC 4:4:4 content in nvdec and cuviddec

  * removed libndi-newtek

  * agm decoder

  * KUX demuxer

  * AV1 frame split bitstream filter

  * lscr decoder

  * lagfun filter

  * asoftclip filter

  * Support decoding of HEVC 4:4:4 content in vdpau

  * colorhold filter

  * xmedian filter

  * asr filter

  * showspatial multimedia filter

  * VP4 video decoder

  * IFV demuxer

  * derain filter

  * deesser filter

  * mov muxer writes tracks with unspecified language instead of English by
  default

  * added support for using clang to compile CUDA kernels

  - See /usr/share/doc/packages/ffmpeg-4/Changelog for the complete
  changelog.

  Update to version 4.1.4

  * See /usr/share/doc/packages/ffmpeg-4/Changelog for the complete
  changelog.

  - Enable runtime enabling for fdkaac via --enable-libfdk-aac-dlopen

  Update to version 4.1.3:

  * Updates and bug fixes for codecs, filters and formats. [boo#1133153,
  boo#1133155, CVE-2019-11338, CVE-2019-11339]

  Update to version 4.1.2:

  * Updates and bug fixes for codecs, filters and formats.

  Update to version 4.1.1:

  * Various filter and codec fixes and enhancements.

  * configure: Add missing xlib dependency for VAAPI X11 code.

  * For complete changelog, see /usr/share/doc/packages/ffmpeg-4/Changelog

  * enable AV1 support on x86_64

  Update ffmpeg to 4.1:

  * Lots of filter updates as usual: deblock, tmix, aplify, fftdnoiz,
  aderivative, aintegral, pal75bars, pal100bars, adeclick, adeclip,
  lensfun (wrapper), colorconstancy, 1D LUT filter (lut1d), cue, acue,
  transpose_npp, amul ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ffmpeg-4' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-debugsource", rpm:"ffmpeg-4-debugsource~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavcodec-devel", rpm:"ffmpeg-4-libavcodec-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavdevice-devel", rpm:"ffmpeg-4-libavdevice-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavfilter-devel", rpm:"ffmpeg-4-libavfilter-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavformat-devel", rpm:"ffmpeg-4-libavformat-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavresample-devel", rpm:"ffmpeg-4-libavresample-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavutil-devel", rpm:"ffmpeg-4-libavutil-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libpostproc-devel", rpm:"ffmpeg-4-libpostproc-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswresample-devel", rpm:"ffmpeg-4-libswresample-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswscale-devel", rpm:"ffmpeg-4-libswscale-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-private-devel", rpm:"ffmpeg-4-private-devel~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58", rpm:"libavcodec58~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58-debuginfo", rpm:"libavcodec58-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58", rpm:"libavdevice58~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58-debuginfo", rpm:"libavdevice58-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7", rpm:"libavfilter7~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7-debuginfo", rpm:"libavfilter7-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58", rpm:"libavformat58~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58-debuginfo", rpm:"libavformat58-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4", rpm:"libavresample4~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4-debuginfo", rpm:"libavresample4-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56", rpm:"libavutil56~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56-debuginfo", rpm:"libavutil56-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55", rpm:"libpostproc55~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55-debuginfo", rpm:"libpostproc55-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3", rpm:"libswresample3~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3-debuginfo", rpm:"libswresample3-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5", rpm:"libswscale5~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5-debuginfo", rpm:"libswscale5-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58-32bit", rpm:"libavcodec58-32bit~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58-32bit-debuginfo", rpm:"libavcodec58-32bit-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58-32bit", rpm:"libavdevice58-32bit~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58-32bit-debuginfo", rpm:"libavdevice58-32bit-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7-32bit", rpm:"libavfilter7-32bit~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7-32bit-debuginfo", rpm:"libavfilter7-32bit-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58-32bit", rpm:"libavformat58-32bit~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58-32bit-debuginfo", rpm:"libavformat58-32bit-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4-32bit", rpm:"libavresample4-32bit~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4-32bit-debuginfo", rpm:"libavresample4-32bit-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56-32bit", rpm:"libavutil56-32bit~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56-32bit-debuginfo", rpm:"libavutil56-32bit-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55-32bit", rpm:"libpostproc55-32bit~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55-32bit-debuginfo", rpm:"libpostproc55-32bit-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3-32bit", rpm:"libswresample3-32bit~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3-32bit-debuginfo", rpm:"libswresample3-32bit-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5-32bit", rpm:"libswscale5-32bit~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5-32bit-debuginfo", rpm:"libswscale5-32bit-debuginfo~4.2.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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