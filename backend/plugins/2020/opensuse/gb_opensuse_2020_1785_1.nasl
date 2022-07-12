# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.853550");
  script_version("2020-11-06T08:04:05+0000");
  script_cve_id("CVE-2020-15673", "CVE-2020-15676", "CVE-2020-15677", "CVE-2020-15678", "CVE-2020-15683", "CVE-2020-15969");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-03 04:01:49 +0000 (Tue, 03 Nov 2020)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2020:1785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1785-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00077.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2020:1785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird and mozilla-nspr fixes the following
  issues:

  - Mozilla Thunderbird 78.4

  * new: MailExtensions: browser.tabs.sendMessage API added

  * new: MailExtensions: messageDisplayScripts API added

  * changed: Yahoo and AOL mail users using password authentication will
  be migrated to OAuth2

  * changed: MailExtensions: messageDisplay APIs extended to support
  multiple selected messages

  * changed: MailExtensions: compose.begin functions now support creating
  a message with attachments

  * fixed: Thunderbird could freeze when updating global search index

  * fixed: Multiple issues with handling of self-signed SSL certificates
  addressed

  * fixed: Recipient address fields in compose window could expand to fill
  all available space

  * fixed: Inserting emoji characters in message compose window caused
  unexpected behavior

  * fixed: Button to restore default folder icon color was not keyboard
  accessible

  * fixed: Various keyboard navigation fixes

  * fixed: Various color-related theme fixes

  * fixed: MailExtensions: Updating attachments with
  onBeforeSend.addListener() did not work MFSA 2020-47 (bsc#1177977)

  * CVE-2020-15969 Use-after-free in usersctp

  * CVE-2020-15683 Memory safety bugs fixed in Thunderbird 78.4

  - Mozilla Thunderbird 78.3.3

  * OpenPGP: Improved support for encrypting with subkeys

  * OpenPGP message status icons were not visible in message header pane

  * Creating a new calendar event did not require an event title

  - Mozilla Thunderbird 78.3.2 (bsc#1176899)

  * OpenPGP: Improved support for encrypting with subkeys

  * OpenPGP: Encrypted messages with international characters were
  sometimes displayed incorrectly

  * Single-click deletion of recipient pills with middle mouse button
  restored

  * Searching an address book list did not display results

  * Dark mode, high contrast, and Windows theming fixes

  - Mozilla Thunderbird 78.3.1

  * fix crash in nsImapProtocol::CreateNewLineFromSocket

  - Mozilla Thunderbird 78.3.0 MFSA 2020-44 (bsc#1176756)

  * CVE-2020-15677 Download origin spoofing via redirect

  * CVE-2020-15676 XSS when pasting attacker-controlled data into a
  contenteditable element

  * CVE-2020-15678 When recursing through layers while scrolling, an
  iterator may have become invalid, resulting in a potential use-after-
  free scenario

  * CVE-2020-15673 Memory safety bugs fixed in Thunderbird 78.3

  - update mozilla-nspr to version 4.25.1

  * The macOS platform code for shared library loading was changed to
  support macOS 11.

  * Dependency needed for the MozillaThunderbird update

  This u ...

  Description truncated. Please see the references for more information.");

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

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.25.1~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.25.1~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.25.1~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.25.1~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~78.4.0~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~78.4.0~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~78.4.0~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~78.4.0~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~78.4.0~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.25.1~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit-debuginfo", rpm:"mozilla-nspr-32bit-debuginfo~4.25.1~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
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
