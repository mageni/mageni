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
  script_oid("1.3.6.1.4.1.25623.1.0.852877");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760",
                "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764",
                "CVE-2019-15903");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:40:31 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE Update for Recommended openSUSE-SU-2019:2452-1 (Recommended)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00018.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Recommended'
  package(s) announced via the openSUSE-SU-2019:2452_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird to version 68.2.1 provides the
  following fixes:

  - Security issues fixed (bsc#1154738):

  * CVE-2019-15903: Fixed a heap overflow in the expat library
  (bsc#1149429).

  * CVE-2019-11757: Fixed a use-after-free when creating index updates in
  IndexedDB (bsc#1154738).

  * CVE-2019-11758: Fixed a potentially exploitable crash due to 360 Total
  Security (bsc#1154738).

  * CVE-2019-11759: Fixed a stack buffer overflow in HKDF output
  (bsc#1154738).

  * CVE-2019-11760: Fixed a stack buffer overflow in WebRTC networking
  (bsc#1154738).

  * CVE-2019-11761: Fixed an unintended access to a privileged JSONView
  object (bsc#1154738).

  * CVE-2019-11762: Fixed a same-origin-property violation (bsc#1154738).

  * CVE-2019-11763: Fixed an XSS bypass (bsc#1154738).

  * CVE-2019-11764: Fixed several memory safety bugs (bsc#1154738).

  Other fixes (bsc#1153879):

  * Some attachments couldn't be opened in messages originating from MS
  Outlook 2016.

  * Address book import from CSV.

  * Performance problem in message body search.

  * Ctrl+Enter to send a message would open an attachment if the
  attachment pane had focus.

  * Calendar: Issues with 'Today Pane' start-up.

  * Calendar: Glitches with custom repeat and reminder number input.

  * Calendar: Problems with WCAP provider.

  * A language for the user interface can now be chosen in the advanced
  settings

  * Fixed an issue with Google authentication (OAuth2)

  * Fixed an issue where selected or unread messages were not shown in the
  correct color in the thread pane under some circumstances

  * Fixed an issue where when using a language pack, names of standard
  folders were not localized (bsc#1149126)

  * Fixed an issue where the address book default startup directory in
  preferences panel not persisted

  * Fixed various visual glitches

  * Fixed issues with the  chat

  * Fixed building with rust >= 1.38.

  * Fixrd LTO build without PGO.

  * Removed kde.js since disabling instantApply breaks extensions and is
  now obsolete with the move to HTML views for preferences. (bsc#1151186)

  * Updated create-tar.sh. (bsc#1152778)

  * Deactivated the crashreporter for the last remaining arch.

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2452=1");

  script_tag(name:"affected", value:"'Recommended' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~68.2.1~lp151.2.16.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~68.2.1~lp151.2.16.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~68.2.1~lp151.2.16.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~68.2.1~lp151.2.16.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~68.2.1~lp151.2.16.1", rls:"openSUSELeap15.1"))) {
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
