###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_0499_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2017:0499-1 (chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851492");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-02-19 05:01:18 +0100 (Sun, 19 Feb 2017)");
  script_cve_id("CVE-2017-5006", "CVE-2017-5007", "CVE-2017-5008", "CVE-2017-5009",
                "CVE-2017-5010", "CVE-2017-5011", "CVE-2017-5012", "CVE-2017-5013",
                "CVE-2017-5014", "CVE-2017-5015", "CVE-2017-5016", "CVE-2017-5017",
                "CVE-2017-5018", "CVE-2017-5019", "CVE-2017-5020", "CVE-2017-5021",
                "CVE-2017-5022", "CVE-2017-5023", "CVE-2017-5024", "CVE-2017-5025",
                "CVE-2017-5026");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for chromium openSUSE-SU-2017:0499-1 (chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Google chromium was updated to 56.0.2924.87:

  * Various small fixes

  * Disabled option to enable/disable plugins in the chrome://plugins

  - Changed the build requirement of libavformat to library version
  57.41.100, as included in ffmpeg 3.1.1, as only this version properly
  supports the public AVStream API 'codecpar'.

  It also contains the version update to 56.0.2924.76  (bsc#1022049):

  - CVE-2017-5007: Universal XSS in Blink

  - CVE-2017-5006: Universal XSS in Blink

  - CVE-2017-5008: Universal XSS in Blink

  - CVE-2017-5010: Universal XSS in Blink

  - CVE-2017-5011: Unauthorised file access in Devtools

  - CVE-2017-5009: Out of bounds memory access in WebRTC

  - CVE-2017-5012: Heap overflow in V8

  - CVE-2017-5013: Address spoofing in Omnibox

  - CVE-2017-5014: Heap overflow in Skia

  - CVE-2017-5015: Address spoofing in Omnibox

  - CVE-2017-5019: Use after free in Renderer

  - CVE-2017-5016: UI spoofing in Blink

  - CVE-2017-5017: Uninitialised memory access in webm video

  - CVE-2017-5018: Universal XSS in chrome://apps

  - CVE-2017-5020: Universal XSS in chrome://downloads

  - CVE-2017-5021: Use after free in Extensions

  - CVE-2017-5022: Bypass of Content Security Policy in Blink

  - CVE-2017-5023: Type confusion in metrics

  - CVE-2017-5024: Heap overflow in FFmpeg

  - CVE-2017-5025: Heap overflow in FFmpeg

  - CVE-2017-5026: UI spoofing. Credit to Ronni Skansing

  - Enable VAAPI hardware accelerated video decoding.

  - Chromium 55.0.2883.87:

  * various fixes for crashes and specific wesites

  * update Google pinned certificates");
  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"ffmpeg3", rpm:"ffmpeg3~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ffmpeg3-debuginfo", rpm:"ffmpeg3-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ffmpeg3-debugsource", rpm:"ffmpeg3-debugsource~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec-devel", rpm:"libavcodec-devel~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice-devel", rpm:"libavdevice-devel~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice57", rpm:"libavdevice57~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice57-debuginfo", rpm:"libavdevice57-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter-devel", rpm:"libavfilter-devel~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter6-debuginfo", rpm:"libavfilter6-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat-devel", rpm:"libavformat-devel~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat57-debuginfo", rpm:"libavformat57-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample3-debuginfo", rpm:"libavresample3-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~56.0.2924.87~102.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~56.0.2924.87~102.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~56.0.2924.87~102.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~56.0.2924.87~102.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~56.0.2924.87~102.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec57-32bit", rpm:"libavcodec57-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavcodec57-debuginfo-32bit", rpm:"libavcodec57-debuginfo-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice57-32bit", rpm:"libavdevice57-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavdevice57-debuginfo-32bit", rpm:"libavdevice57-debuginfo-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter6-32bit", rpm:"libavfilter6-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter6-debuginfo-32bit", rpm:"libavfilter6-debuginfo-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat57-32bit", rpm:"libavformat57-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformat57-debuginfo-32bit", rpm:"libavformat57-debuginfo-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample3-32bit", rpm:"libavresample3-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavresample3-debuginfo-32bit", rpm:"libavresample3-debuginfo-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil55-32bit", rpm:"libavutil55-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil55-debuginfo-32bit", rpm:"libavutil55-debuginfo-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc54-32bit", rpm:"libpostproc54-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc54-debuginfo-32bit", rpm:"libpostproc54-debuginfo-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample2-32bit", rpm:"libswresample2-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswresample2-debuginfo-32bit", rpm:"libswresample2-debuginfo-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale4-32bit", rpm:"libswscale4-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscale4-debuginfo-32bit", rpm:"libswscale4-debuginfo-32bit~3.2.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
