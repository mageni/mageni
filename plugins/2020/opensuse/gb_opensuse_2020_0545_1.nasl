# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.853122");
  script_version("2020-04-26T06:11:04+0000");
  script_cve_id("CVE-2019-13602", "CVE-2019-13962", "CVE-2019-14437", "CVE-2019-14438", "CVE-2019-14498", "CVE-2019-14533", "CVE-2019-14534", "CVE-2019-14535", "CVE-2019-14776", "CVE-2019-14777", "CVE-2019-14778", "CVE-2019-14970");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-27 10:07:29 +0000 (Mon, 27 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-24 03:00:46 +0000 (Fri, 24 Apr 2020)");
  script_name("openSUSE: Security Advisory for vlc (openSUSE-SU-2020:0545-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00036.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc'
  package(s) announced via the openSUSE-SU-2020:0545-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vlc fixes the following issues:

  vlc was updated to version 3.0.9.2:

  + Misc: Properly bump the version in configure.ac.

  Changes from version 3.0.9.1:

  + Misc: Fix VLSub returning 401 for search request.

  Changes from version 3.0.9:

  + Core: Work around busy looping when playing an invalid item through VLM.
  + Access:

  * Multiple dvdread and dvdnav crashes fixes

  * Fixed DVD glitches on clip change

  * Fixed dvdread commands/data sequence inversion in some cases causing
  unwanted glitches

  * Better handling of authored as corrupted DVD

  * Added libsmb2 support for SMB2/3 shares
  + Demux:

  * Fix TTML entities not passed to decoder

  * Fixed some WebVTT styling tags being not applied

  * Misc raw H264/HEVC frame rate fixes

  * Fix adaptive regression on TS format change (mostly HLS)

  * Fixed MP4 regression with twos/sowt PCM audio

  * Fixed some MP4 raw quicktime and ms-PCM audio

  * Fixed MP4 interlacing handling

  * Multiple adaptive stack (DASH/HLS/Smooth) fixes

  * Enabled Live seeking for HLS

  * Fixed seeking in some cases for HLS

  * Improved Live playback for Smooth and DASH

  * Fixed adaptive unwanted end of stream in some cases

  * Faster adaptive start and new buffering control options
  + Packetizers:

  * Fixes H264/HEVC incomplete draining in some cases

  * packetizer_helper: Fix potential trailing junk on last packet

  * Added missing drain in packetizers that was causing missing last frame
  or audio

  * Improved check to prevent fLAC synchronization drops
  + Decoder:

  * avcodec: revector video decoder to fix incomplete drain

  * spudec: implemented palette updates, fixing missing subtitles
  on some DVD

  * Fixed WebVTT CSS styling not being applied on Windows/macOS

  * Fixed Hebrew teletext pages support in zvbi

  * Fixed Dav1d aborting decoding on corrupted picture

  * Extract and display of all CEA708 subtitles

  * Update libfaad to 2.9.1

  * Add DXVA support for VP9 Profile 2 (10 bits)

  * Mediacodec aspect ratio with Amazon devices
  + Audio output:

  * Added support for iOS audiounit audio above 48KHz

  * Added support for amem audio up to 384KHz
  + Video output:

  * Fix for opengl glitches in some drivers

  * Fix GMA950 opengl support on macOS

  * YUV to RGB StretchRect fixes with NVIDIA drivers

  * Use libpacebo new tone mapping desaturation algorithm
  + Text renderer:

  * Fix crashes on macOS with SSA/ASS subtitles containing emoji

  * Fixed unwanted growing background in Freetype rendering and Y padding
  + Mux: Fixed some YUV mappings
  + Service Discovery: Update libmicrodns to 0.1.2.
  + Misc:

  * Update YouTube, SoundCloud  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'vlc' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"vlc-lang", rpm:"vlc-lang~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5-debuginfo", rpm:"libvlc5-debuginfo~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9", rpm:"libvlccore9~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9-debuginfo", rpm:"libvlccore9-debuginfo~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-codec-gstreamer", rpm:"vlc-codec-gstreamer~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-codec-gstreamer-debuginfo", rpm:"vlc-codec-gstreamer-debuginfo~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-debuginfo", rpm:"vlc-debuginfo~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-debugsource", rpm:"vlc-debugsource~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-devel", rpm:"vlc-devel~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-jack", rpm:"vlc-jack~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-jack-debuginfo", rpm:"vlc-jack-debuginfo~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-noX", rpm:"vlc-noX~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-noX-debuginfo", rpm:"vlc-noX-debuginfo~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-opencv", rpm:"vlc-opencv~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-opencv-debuginfo", rpm:"vlc-opencv-debuginfo~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-qt", rpm:"vlc-qt~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-qt-debuginfo", rpm:"vlc-qt-debuginfo~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-vdpau", rpm:"vlc-vdpau~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-vdpau-debuginfo", rpm:"vlc-vdpau-debuginfo~3.0.9.2~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
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
