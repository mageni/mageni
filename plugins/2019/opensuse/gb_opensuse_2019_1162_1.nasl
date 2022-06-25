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
  script_oid("1.3.6.1.4.1.25623.1.0.852404");
  script_version("2019-04-06T02:01:00+0000");
  script_cve_id("CVE-2018-18335", "CVE-2018-18356", "CVE-2018-18506", "CVE-2018-18509",
                "CVE-2019-5785", "CVE-2019-9788", "CVE-2019-9790", "CVE-2019-9791",
                "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9794", "CVE-2019-9795",
                "CVE-2019-9796", "CVE-2019-9801", "CVE-2019-9810", "CVE-2019-9813");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-06 02:01:00 +0000 (Sat, 06 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-06 02:01:00 +0000 (Sat, 06 Apr 2019)");
  script_name("openSUSE Update for MozillaThunderbird openSUSE-SU-2019:1162-1 (MozillaThunderbird)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00043.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2019:1162_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird to version 60.5.1 fixes the following
  issues:

  Security issues fixed:

  - Update to MozillaThunderbird 60.6.1 (bsc#1130262):

  - CVE-2019-9813: Fixed Ionmonkey type confusion with __proto__ mutations

  - CVE-2019-9810: Fixed IonMonkey MArraySlice incorrect alias information

  - Update to MozillaThunderbird 60.6 (bsc#1129821):

  - CVE-2018-18506: Fixed an issue with Proxy Auto-Configuration file

  - CVE-2019-9801: Fixed an issue which could allow Windows programs to be
  exposed to web content

  - CVE-2019-9788: Fixed multiple memory safety bugs

  - CVE-2019-9790: Fixed a Use-after-free vulnerability when removing in-use
  DOM elements

  - CVE-2019-9791: Fixed an incorrect Type inference for constructors
  entered through on-stack replacement with IonMonkey

  - CVE-2019-9792: Fixed an issue where IonMonkey leaks JS_OPTIMIZED_OUT
  magic value to script

  - CVE-2019-9793: Fixed multiple improper bounds checks when Spectre
  mitigations are disabled

  - CVE-2019-9794: Fixed an issue where command line arguments not discarded
  during execution

  - CVE-2019-9795: Fixed a Type-confusion vulnerability in IonMonkey JIT
  compiler

  - CVE-2019-9796: Fixed a Use-after-free vulnerability in SMIL animation
  controller

  - Update to MozillaThunderbird 60.5.1 (bsc#1125330):

  - CVE-2018-18356: Fixed a use-after-free vulnerability in the Skia library
  which can occur when creating a path, leading to a potentially
  exploitable crash.

  - CVE-2019-5785: Fixed an integer overflow vulnerability in the Skia
  library which can occur after specific transform operations, leading to
  a potentially exploitable crash.

  - CVE-2018-18335: Fixed a buffer overflow vulnerability in the Skia
  library which can occur with Canvas 2D acceleration on macOS. This issue
  was addressed by disabling Canvas 2D acceleration in Firefox ESR.  Note:
  this does not affect other versions and platforms where Canvas 2D
  acceleration is already disabled by default.

  - CVE-2018-18509: Fixed a flaw which during verification of certain S/MIME
  signatures showing mistakenly that emails bring a valid sugnature.

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~60.6.1~lp150.3.37.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~60.6.1~lp150.3.37.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~60.6.1~lp150.3.37.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~60.6.1~lp150.3.37.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~60.6.1~lp150.3.37.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~60.6.1~lp150.3.37.1", rls:"openSUSELeap15.0"))) {
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
