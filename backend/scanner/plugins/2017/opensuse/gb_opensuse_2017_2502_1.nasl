###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2502_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for ffmpeg, openSUSE-SU-2017:2502-1 (ffmpeg,)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851617");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-09-16 07:27:03 +0200 (Sat, 16 Sep 2017)");
  script_cve_id("CVE-2016-10190", "CVE-2016-10191", "CVE-2016-10192", "CVE-2016-9561",
                "CVE-2017-11399", "CVE-2017-14054", "CVE-2017-14055", "CVE-2017-14056",
                "CVE-2017-14057", "CVE-2017-14058", "CVE-2017-14059", "CVE-2017-14169",
                "CVE-2017-14170", "CVE-2017-14171", "CVE-2017-14222", "CVE-2017-14223",
                "CVE-2017-14225", "CVE-2017-7863", "CVE-2017-7865", "CVE-2017-7866");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ffmpeg, openSUSE-SU-2017:2502-1 (ffmpeg, )");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg.'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update introduces lame and twolame.

  For ffmpeg2 it updates to version 2.8.13 and fixes several issues.

  These security issues were fixed:

  - CVE-2017-14058: The read_data function in libavformat/hls.c did not
  restrict reload attempts for an insufficient list, which allowed remote
  attackers to cause a denial of service (infinite loop) (bsc#1056762).

  - CVE-2017-14057: In asf_read_marker() due to lack of an EOF (End of File)
  check might have caused huge CPU and memory consumption. When a crafted
  ASF file, which claims a large 'name_len' or 'count' field in the header
  but did not contain sufficient backing data, was provided, the loops
  over the name and markers would consume huge CPU and memory resources,
  since there is no EOF check inside these loops (bsc#1056761).

  - CVE-2017-14059: A DoS in cine_read_header() due to lack of an EOF check
  might have caused huge CPU and memory consumption. When a crafted CINE
  file, which claims a large 'duration' field in the header but did not
  contain sufficient backing data, was provided, the image-offset parsing
  loop would consume huge CPU and memory resources, since there is no EOF
  check inside the loop (bsc#1056763).

  - CVE-2017-14056: A DoS in rl2_read_header() due to lack of an EOF (End of
  File) check might have caused huge CPU and memory consumption. When a
  crafted RL2 file, which claims a large 'frame_count' field in the header
  but did not contain sufficient backing data, was provided, the loops
  (for offset and size tables) would consume huge CPU and memory
  resources, since there is no EOF check inside these loops (bsc#1056760).

  - CVE-2017-14055: a DoS in mv_read_header() due to lack of an EOF (End of
  File) check might have caused huge CPU and memory consumption. When a
  crafted MV file, which claims a large 'nb_frames' field in the header
  but did not contain sufficient backing data, was provided, the loop over
  the frames would consume huge CPU and memory resources, since there is
  no EOF check inside the loop (bsc#1056766).

  - boo#1046211: Lots of integer overflow fixes

  - CVE-2016-9561: The che_configure function in
  libavcodec/aacdec_template.c in FFmpeg allowed remote attackers to cause
  a denial of service (allocation of huge memory, and being killed by the
  OS) via a crafted MOV file (boo#1015120)

  - CVE-2017-7863: FFmpeg had an out-of-bounds write caused by a heap-based
  buffer overflow related to the decode_frame_common function in
  libavcodec/pngdec.c (boo#1034179)

  - CVE-2017-7865: FFmpeg had an out-of-bounds write caused by a heap-based
  buffer overflow related to t ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ffmpeg, on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ffmpeg2-debugsource", rpm:"ffmpeg2-debugsource~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ffmpeg2-devel", rpm:"ffmpeg2-devel~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame", rpm:"lame~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-debuginfo", rpm:"lame-debuginfo~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-debugsource", rpm:"lame-debugsource~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-doc", rpm:"lame-doc~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-mp3rtp", rpm:"lame-mp3rtp~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-mp3rtp-debuginfo", rpm:"lame-mp3rtp-debuginfo~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec-devel", rpm:"libavcodec-devel~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec56", rpm:"libavcodec56~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec56-debuginfo", rpm:"libavcodec56-debuginfo~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice-devel", rpm:"libavdevice-devel~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice56", rpm:"libavdevice56~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice56-debuginfo", rpm:"libavdevice56-debuginfo~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice57", rpm:"libavdevice57~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice57-debuginfo", rpm:"libavdevice57-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter-devel", rpm:"libavfilter-devel~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter5", rpm:"libavfilter5~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter5-debuginfo", rpm:"libavfilter5-debuginfo~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter6-debuginfo", rpm:"libavfilter6-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat-devel", rpm:"libavformat-devel~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat56", rpm:"libavformat56~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat56-debuginfo", rpm:"libavformat56-debuginfo~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat57-debuginfo", rpm:"libavformat57-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample2", rpm:"libavresample2~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample2-debuginfo", rpm:"libavresample2-debuginfo~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample3-debuginfo", rpm:"libavresample3-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil54", rpm:"libavutil54~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil54-debuginfo", rpm:"libavutil54-debuginfo~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame-devel", rpm:"libmp3lame-devel~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame0", rpm:"libmp3lame0~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame0-debuginfo", rpm:"libmp3lame0-debuginfo~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc53", rpm:"libpostproc53~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc53-debuginfo", rpm:"libpostproc53-debuginfo~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample1", rpm:"libswresample1~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample1-debuginfo", rpm:"libswresample1-debuginfo~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale3", rpm:"libswscale3~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale3-debuginfo", rpm:"libswscale3-debuginfo~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtwolame-devel", rpm:"libtwolame-devel~0.3.13~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtwolame0", rpm:"libtwolame0~0.3.13~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtwolame0-debuginfo", rpm:"libtwolame0-debuginfo~0.3.13~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"twolame", rpm:"twolame~0.3.13~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"twolame-debuginfo", rpm:"twolame-debuginfo~0.3.13~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"twolame-debugsource", rpm:"twolame-debugsource~0.3.13~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec56-32bit", rpm:"libavcodec56-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec56-debuginfo-32bit", rpm:"libavcodec56-debuginfo-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec57-32bit", rpm:"libavcodec57-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec57-debuginfo-32bit", rpm:"libavcodec57-debuginfo-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice56-32bit", rpm:"libavdevice56-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice56-debuginfo-32bit", rpm:"libavdevice56-debuginfo-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice57-32bit", rpm:"libavdevice57-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice57-debuginfo-32bit", rpm:"libavdevice57-debuginfo-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter5-32bit", rpm:"libavfilter5-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter5-debuginfo-32bit", rpm:"libavfilter5-debuginfo-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter6-32bit", rpm:"libavfilter6-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter6-debuginfo-32bit", rpm:"libavfilter6-debuginfo-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat56-32bit", rpm:"libavformat56-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat56-debuginfo-32bit", rpm:"libavformat56-debuginfo-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat57-32bit", rpm:"libavformat57-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat57-debuginfo-32bit", rpm:"libavformat57-debuginfo-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample2-32bit", rpm:"libavresample2-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample2-debuginfo-32bit", rpm:"libavresample2-debuginfo-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample3-32bit", rpm:"libavresample3-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample3-debuginfo-32bit", rpm:"libavresample3-debuginfo-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil54-32bit", rpm:"libavutil54-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil54-debuginfo-32bit", rpm:"libavutil54-debuginfo-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil55-32bit", rpm:"libavutil55-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil55-debuginfo-32bit", rpm:"libavutil55-debuginfo-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame0-32bit", rpm:"libmp3lame0-32bit~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame0-debuginfo-32bit", rpm:"libmp3lame0-debuginfo-32bit~3.99.5~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc53-32bit", rpm:"libpostproc53-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc53-debuginfo-32bit", rpm:"libpostproc53-debuginfo-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc54-32bit", rpm:"libpostproc54-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc54-debuginfo-32bit", rpm:"libpostproc54-debuginfo-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample1-32bit", rpm:"libswresample1-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample1-debuginfo-32bit", rpm:"libswresample1-debuginfo-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample2-32bit", rpm:"libswresample2-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample2-debuginfo-32bit", rpm:"libswresample2-debuginfo-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale3-32bit", rpm:"libswscale3-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale3-debuginfo-32bit", rpm:"libswscale3-debuginfo-32bit~2.8.13~32.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale4-32bit", rpm:"libswscale4-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale4-debuginfo-32bit", rpm:"libswscale4-debuginfo-32bit~3.3.4~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtwolame0-32bit", rpm:"libtwolame0-32bit~0.3.13~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtwolame0-debuginfo-32bit", rpm:"libtwolame0-debuginfo-32bit~0.3.13~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
