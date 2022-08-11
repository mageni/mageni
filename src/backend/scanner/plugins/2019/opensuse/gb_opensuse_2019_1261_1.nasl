# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852443");
  script_version("2019-04-25T10:19:44+0000");
  script_cve_id("CVE-2019-7572", "CVE-2019-7573", "CVE-2019-7574", "CVE-2019-7575",
                "CVE-2019-7576", "CVE-2019-7577", "CVE-2019-7578", "CVE-2019-7635",
                "CVE-2019-7636", "CVE-2019-7637", "CVE-2019-7638");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-25 10:19:44 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-24 02:01:07 +0000 (Wed, 24 Apr 2019)");
  script_name("openSUSE Update for SDL2 openSUSE-SU-2019:1261-1 (SDL2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00088.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL2'
  package(s) announced via the openSUSE-SU-2019:1261_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL2 fixes the following issues:

  Security issues fixed:

  - CVE-2019-7572: Fixed a buffer over-read in IMA_ADPCM_nibble in
  audio/SDL_wave.c.(bsc#1124806).

  - CVE-2019-7578: Fixed a heap-based buffer over-read in InitIMA_ADPCM in
  audio/SDL_wave.c (bsc#1125099).

  - CVE-2019-7576: Fixed heap-based buffer over-read in InitMS_ADPCM in
  audio/SDL_wave.c (bsc#1124799).

  - CVE-2019-7573: Fixed a heap-based buffer over-read in InitMS_ADPCM in
  audio/SDL_wave.c (bsc#1124805).

  - CVE-2019-7635: Fixed a heap-based buffer over-read in Blit1to4 in
  video/SDL_blit_1.c. (bsc#1124827).

  - CVE-2019-7636: Fixed a heap-based buffer over-read in SDL_GetRGB in
  video/SDL_pixels.c (bsc#1124826).

  - CVE-2019-7638: Fixed a heap-based buffer over-read in Map1toN in
  video/SDL_pixels.c (bsc#1124824).

  - CVE-2019-7574: Fixed a heap-based buffer over-read in IMA_ADPCM_decode
  in audio/SDL_wave.c (bsc#1124803).

  - CVE-2019-7575: Fixed a heap-based buffer overflow in MS_ADPCM_decode in
  audio/SDL_wave.c (bsc#1124802).

  - CVE-2019-7637: Fixed a heap-based buffer overflow in SDL_FillRect
  function in SDL_surface.c (bsc#1124825).

  - CVE-2019-7577: Fixed a buffer over read in SDL_LoadWAV_RW in
  audio/SDL_wave.c (bsc#1124800).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1261=1");

  script_tag(name:"affected", value:"'SDL2' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"SDL2-debugsource", rpm:"SDL2-debugsource~2.0.8~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0", rpm:"libSDL2-2_0-0~2.0.8~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-debuginfo", rpm:"libSDL2-2_0-0-debuginfo~2.0.8~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-devel", rpm:"libSDL2-devel~2.0.8~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-32bit", rpm:"libSDL2-2_0-0-32bit~2.0.8~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-32bit-debuginfo", rpm:"libSDL2-2_0-0-32bit-debuginfo~2.0.8~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-devel-32bit", rpm:"libSDL2-devel-32bit~2.0.8~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
