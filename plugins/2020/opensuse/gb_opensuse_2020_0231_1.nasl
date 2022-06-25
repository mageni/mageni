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
  script_oid("1.3.6.1.4.1.25623.1.0.853041");
  script_version("2020-02-20T11:12:08+0000");
  script_cve_id("CVE-2020-6792", "CVE-2020-6793", "CVE-2020-6794", "CVE-2020-6795", "CVE-2020-6797", "CVE-2020-6798", "CVE-2020-6800");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-02-20 11:12:08 +0000 (Thu, 20 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-19 04:02:08 +0000 (Wed, 19 Feb 2020)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2020:0231-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00023.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2020:0231-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  - Mozilla Thunderbird 68.5 (bsc#1162777) MFSA 2020-07 (bsc#1163368)

  * CVE-2020-6793 (bmo#1608539) Out-of-bounds read when processing certain
  email messages

  * CVE-2020-6794 (bmo#1606619) Setting a master password post-Thunderbird
  52 does not delete unencrypted previously stored passwords

  * CVE-2020-6795 (bmo#1611105) Crash processing S/MIME messages with
  multiple signatures

  * CVE-2020-6797 (bmo#1596668) Extensions granted downloads.open
  permission could open arbitrary applications on Mac OSX

  * CVE-2020-6798 (bmo#1602944) Incorrect parsing of template tag could
  result in JavaScript injection

  * CVE-2020-6792 (bmo#1609607) Message ID calculation was based on
  uninitialized data

  * CVE-2020-6800 (bmo#1595786, bmo#1596706, bmo#1598543, bmo#1604851,
  bmo#1605777, bmo#1608580, bmo#1608785) Memory safety bugs fixed in
  Thunderbird 68.5

  * new: Support for Client Identity IMAP/SMTP Service Extension
  (bmo#1532388)

  * new: Support for OAuth 2.0 authentication for POP3 accounts
  (bmo#1538409)

  * fixed: Status area goes blank during account setup (bmo#1593122)

  * fixed: Calendar: Could not remove color for default categories
  (bmo#1584853)

  * fixed: Calendar: Prevent calendar component loading multiple times
  (bmo#1606375)

  * fixed: Calendar: Today pane did not retain width between sessions
  (bmo#1610207)

  * unresolved: When upgrading from Thunderbird version 60 to version 68,
  add-ons are not automatically updated during the upgrade process. They
  will however be updated during the add-
  on update check. It is of course possible to reinstall compatible
  add-ons via the Add-ons Manager or via addons.thunderbird.net.
  (bmo#1574183)

  * changed: Calendar: Task and Event tree colours adjusted for the dark
  theme (bmo#1608344)

  * fixed: Retrieval of S/MIME certificates from LDAP failed (bmo#1604773)

  * fixed: Address-parsing crash on some IMAP servers when preference
  mail.imap.use_envelope_cmd was set (bmo#1609690)

  * fixed: Incorrect forwarding of HTML messages caused SMTP servers to
  respond with a timeout (bmo#1222046)

  * fixed: Calendar: Various parts of the calendar UI stopped working when
  a second Thunderbird window opened (bmo#1608407)


  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-231=1");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~68.5.0~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~68.5.0~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~68.5.0~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~68.5.0~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~68.5.0~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
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
