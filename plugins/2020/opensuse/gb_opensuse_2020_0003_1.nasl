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
  script_oid("1.3.6.1.4.1.25623.1.0.852974");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2019-17008", "CVE-2019-13722", "CVE-2019-11745", "CVE-2019-17009", "CVE-2019-17010", "CVE-2019-17005", "CVE-2019-17011", "CVE-2019-17012");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-10 03:00:29 +0000 (Fri, 10 Jan 2020)");
  script_name("openSUSE Update for MozillaThunderbird openSUSE-SU-2020:0003-1 (MozillaThunderbird)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00000.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2020:0003_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  Mozilla Thunderbird was updated to 68.3esr (MFSA 2019-38 bsc#1158328)

  Security issues fixed:

  - CVE-2019-17008: Fixed a use-after-free in worker destruction
  (bmo#1546331)

  - CVE-2019-13722: Fixed a stack corruption due to incorrect number of
  arguments in WebRTC code (bmo#1580156)

  - CVE-2019-11745: Fixed an out of bounds write in NSS when encrypting with
  a block cipher (bmo#1586176)

  - CVE-2019-17009: Fixed an issue where updater temporary files accessible
  to unprivileged processes (bmo#1510494)

  - CVE-2019-17010: Fixed a use-after-free when performing device
  orientation checks (bmo#1581084)

  - CVE-2019-17005: Fixed a buffer overflow in plain text serializer
  (bmo#1584170)

  - CVE-2019-17011: Fixed a use-after-free when retrieving a document in
  antitracking (bmo#1591334)

  - CVE-2019-17012: Fixed multiple memory issues (bmo#1449736, bmo#1533957,
  bmo#1560667, bmo#1567209, bmo#1580288, bmo#1585760, bmo#1592502)

  Other issues addressed:

  - New: Message display toolbar action WebExtension API (bmo#1531597)

  - New: Navigation buttons are now available in content tabs (bmo#787683)

  - Fixed an issue where write window was not always correct (bmo#1593280)

  - Fixed toolbar issues (bmo#1584160)

  - Fixed issues with LDAP lookup when SSL was enabled (bmo#1576364)

  - Fixed an issue with scam link confirmation panel (bmo#1596413)

  - Fixed an issue with the write window where the Link Properties dialog
  was not showing named anchors in context menu (bmo#1593629)

  - Fixed issues with calendar (bmo#1588516)

  - Fixed issues with chat where reordering via drag-and-drop was not working
  on Instant messaging status dialog (bmo#1591505)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-3=1");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~68.3.0~lp151.2.19.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~68.3.0~lp151.2.19.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~68.3.0~lp151.2.19.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~68.3.0~lp151.2.19.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~68.3.0~lp151.2.19.1", rls:"openSUSELeap15.1"))) {
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
