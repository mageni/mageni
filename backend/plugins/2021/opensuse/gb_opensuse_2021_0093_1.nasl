# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853744");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2020-16044");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:02:31 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2021:0093-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0093-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/72PBD5PFZIW6WZ7R65QRFVISRDWYC6WO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2021:0093-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  - Mozilla Thunderbird 78.6.1

  * changed: MailExtensions: browserAction, composeAction, and
         messageDisplayAction toolbar buttons now support label and
         default_label properties (bmo#1583478)

  * fixed: Running a quicksearch that returned no results did not
         offer to re-run as a global search (bmo#1663153)

  * fixed: Message search toolbar fixes (bmo#1681010)

  * fixed: Very long subject lines distorted the message compose and
         display windows, making them unusable (bmo#77806)

  * fixed: Compose window: Recipient addresses that had not yet been
         autocompleted were lost when clicking Send button (bmo#1674054)

  * fixed: Compose window: New message is no longer marked as 'changed'
         just from tabbing out of the recipient field without editing anything
         (bmo#1681389)

  * fixed: Account autodiscover fixes when using MS Exchange servers
         (bmo#1679759)

  * fixed: LDAP address book stability fix (bmo#1680914)

  * fixed: Messages with invalid vcard attachments were not marked as read
         when viewed in the preview window (bmo#1680468)

  * fixed: Chat: Could not add TLS certificate exceptions for XMPP
         connections (bmo#1590471)

  * fixed: Calendar: System timezone was not always properly detected
         (bmo#1678839)

  * fixed: Calendar: Descriptions were sometimes blank when editing a
         single occurrence of a repeating event (bmo#1664731)

  * fixed: Various printing bugfixes (bmo#1676166)

  * fixed: Visual consistency and theme improvements (bmo#1682808) MFSA
         2021-02 (bsc#1180623)

  * CVE-2020-16044 (bmo#1683964) Use-after-free write when handling a
         malicious COOKIE-ECHO SCTP chunk

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~78.6.1~lp152.2.26.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~78.6.1~lp152.2.26.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~78.6.1~lp152.2.26.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~78.6.1~lp152.2.26.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~78.6.1~lp152.2.26.1", rls:"openSUSELeap15.2"))) {
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