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
  script_oid("1.3.6.1.4.1.25623.1.0.852692");
  script_version("2019-09-10T08:05:24+0000");
  script_cve_id("CVE-2019-13616", "CVE-2019-5052", "CVE-2019-5057", "CVE-2019-5058", "CVE-2019-5059", "CVE-2019-5060", "CVE-2019-7635");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-10 08:05:24 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-06 02:00:59 +0000 (Fri, 06 Sep 2019)");
  script_name("openSUSE Update for SDL_image openSUSE-SU-2019:2071-1 (SDL_image)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00014.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL_image'
  package(s) announced via the openSUSE-SU-2019:2071_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL_image fixes the following issues:

  Update SDL_Image to new snapshot 1.2.12+hg695.

  Security issues fixed:

  * TALOS-2019-0821 CVE-2019-5052: exploitable integer overflow
  vulnerability when loading a PCX file (boo#1140421)

  * TALOS-2019-0841 CVE-2019-5057: code execution vulnerability in the PCX
  image-rendering functionality of SDL2_image (boo#1143763)

  * TALOS-2019-0842 CVE-2019-5058: heap overflow in XCF image rendering can
  lead to code execution (boo#1143764)

  * TALOS-2019-0843 CVE-2019-5059: heap overflow in XPM image handling
  (boo#1143766)

  * TALOS-2019-0844 CVE-2019-5060: integer overflow in the XPM image
  (boo#1143768)

  * CVE-2019-7635: heap-based buffer over-read in Blit1to4 in
  video/SDL_blit_1.c (boo#1124827)

  * CVE-2019-13616: fix heap buffer overflow when reading a crafted bmp file
  (boo#1141844).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2071=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2071=1");

  script_tag(name:"affected", value:"'SDL_image' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"SDL_image-debugsource", rpm:"SDL_image-debugsource~1.2.12+hg695~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image-1_2-0", rpm:"libSDL_image-1_2-0~1.2.12+hg695~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image-1_2-0-debuginfo", rpm:"libSDL_image-1_2-0-debuginfo~1.2.12+hg695~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image-devel", rpm:"libSDL_image-devel~1.2.12+hg695~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image-1_2-0-32bit", rpm:"libSDL_image-1_2-0-32bit~1.2.12+hg695~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image-1_2-0-32bit-debuginfo", rpm:"libSDL_image-1_2-0-32bit-debuginfo~1.2.12+hg695~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image-devel-32bit", rpm:"libSDL_image-devel-32bit~1.2.12+hg695~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
