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
  script_oid("1.3.6.1.4.1.25623.1.0.852804");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2018-18541", "CVE-2019-10877", "CVE-2019-10878", "CVE-2019-10879");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:31:48 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE Update for teeworlds openSUSE-SU-2019:1793-1 (teeworlds)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00046.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'teeworlds'
  package(s) announced via the openSUSE-SU-2019:1793_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for teeworlds fixes the following issues:

  - CVE-2019-10879: An integer overflow in CDataFileReader::Open() could
  have lead to a buffer overflow and possibly remote code execution,
  because size-related multiplications were mishandled. (boo#1131729)

  - CVE-2019-10878: A failed bounds check in CDataFileReader::GetData() and
  CDataFileReader::ReplaceData() and related functions could have lead to
  an arbitrary free and out-of-bounds pointer write, possibly resulting in
  remote code execution.

  - CVE-2019-10877: An integer overflow in CMap::Load() could have lead to a
  buffer overflow, because multiplication of width and height were
  mishandled.

  - CVE-2018-18541: Connection packets could have been forged. There was no
  challenge-response involved in the connection build up. A remote
  attacker could have sent connection packets from a spoofed IP address
  and occupy all server slots, or even use them for a reflection attack
  using map download packets. (boo#1112910)

  - Update to version 0.7.3.1

  * Colorful gametype and level icons in the browser instead of grayscale.

  * Add an option to use raw mouse inputs, revert to (0.6) relative mode
  by default.

  * Demo list marker indicator.

  * Restore ingame Player and Tee menus, add a warning that a reconnect is
  needed.

  * Emotes can now be cancelled by releasing the mouse in the middle of
  the circle.

  * Improve add friend text.

  * Add a confirmation for removing a filter

  * Add a 'click a player to follow' hint

  * Also hint players which key they should press to set themselves ready.

  * fixed using correct array measurements when placing egg doodads

  * fixed demo recorder downloaded maps using the sha256 hash

  * show correct game release version in the start menu and console

  * Fix platform-specific client libraries for Linux

  * advanced scoreboard with game statistics

  * joystick support (experimental!)

  * copy paste (one-way)

  * bot cosmetics (a visual difference between players and NPCs)

  * chat commands (type / in chat)

  * players can change skin without leaving the server (again)

  * live automapper and complete rules for 0.7 tilesets

  * audio toggling HUD

  * an Easter surprise...

  * new gametypes:'last man standing' (LMS) and 'last team standing'
  (LTS). survive by your own or as a team with limited weaponry

  * 64 players support. official gametypes are still restricted to 16
  players maximum but allow more spectators

  * new skin system. build your own skins based on a variety of provided
  parts

  * enhanced security. all communications require a handshake and use a
  token to  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'teeworlds' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"teeworlds", rpm:"teeworlds~0.7.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"teeworlds-debuginfo", rpm:"teeworlds-debuginfo~0.7.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"teeworlds-debugsource", rpm:"teeworlds-debugsource~0.7.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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
