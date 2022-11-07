# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3800.1");
  script_cve_id("CVE-2022-3155", "CVE-2022-3266", "CVE-2022-39236", "CVE-2022-39249", "CVE-2022-39250", "CVE-2022-39251", "CVE-2022-40956", "CVE-2022-40957", "CVE-2022-40958", "CVE-2022-40959", "CVE-2022-40960", "CVE-2022-40962");
  script_tag(name:"creation_date", value:"2022-10-28 04:36:32 +0000 (Fri, 28 Oct 2022)");
  script_version("2022-10-28T04:36:32+0000");
  script_tag(name:"last_modification", value:"2022-10-28 04:36:32 +0000 (Fri, 28 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 15:35:00 +0000 (Fri, 30 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3800-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3800-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223800-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2022:3800-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Mozilla Thunderbird 102.4.0 (bsc#1204421)
 * changed: Thunderbird will automatically detect and repair OpenPGP key
 storage corruption caused by using the profile import tool in
 Thunderbird 102
 * fixed: POP message download into a large folder (~13000 messages)
 caused Thunderbird to temporarily freeze
 * fixed: Forwarding messages with special characters in Subject failed
 on Windows
 * fixed: Links for FileLink attachments were not added when attachment
 filename contained Unicode characters
 * fixed: Address Book display pane continued to show contacts after
 deletion
 * fixed: Printing address book did not include all contact details
 * fixed: CardDAV contacts without a Name property did not save to Google
 Contacts
 * fixed: 'Publish Calendar' did not work
 * fixed: Calendar database storage improvements
 * fixed: Incorrectly handled error responses from CalDAV servers
 sometimes caused events to disappear from calendar
 * fixed: Various visual and UX improvements

Mozilla Thunderbird 102.3.3
 * new: Option added to show containing address book for a contact when
 using `All Address Books` in vertical mode (bmo#1778871)
 * changed: Thunderbird will try to use POP NTLM authentication even if
 not advertised by server (bmo#1793349)
 * changed: Task List and Today Pane sidebars will no longer load when
 not visible (bmo#1788549)
 * fixed: Sending a message while a recipient pill was being modified did
 not save changes (bmo#1779785)
 * fixed: Nickname column was not available in horizontal view
 of Address Book (bmo#1778000)
 * fixed: Multiline organization values were displayed across two columns
 in horizontal view of Address Book (bmo#1777780)
 * fixed: Contact vCard fields with multiple values such as Categories
 were truncated when saved (bmo#1792399)
 * fixed: ICS calendar files with a `FREEBUSY` property could not be
 imported (bmo#1783441)
 * fixed: Thunderbird would hang if calendar event exceeded the year 2035
 (bmo#1789999)

Mozilla Thunderbird 102.3.2
 * changed: Thunderbird will try to use POP CRAM-MD5 authentication even
 if not advertised by server (bmo#1789975)
 * fixed: Checking messages on POP3 accounts caused POP folder to lock if
 mail server was slow or non-responsive (bmo#1792451)
 * fixed: Newsgroups named with consecutive dots would not appear when
 refreshing list of newsgroups (bmo#1787789)
 * fixed: Sending news articles containing lines starting with dot were
 sometimes clipped (bmo#1787955)
 * fixed: CardDAV server sync silently failed if sync token expired
 (bmo#1791183)
 * fixed: Contacts from LDAP on macOS address books were not displayed
 (bmo#1791347)
 * fixed: Chat account input now accepts URIs for supported chat
 protocols (bmo#1776706)
 * fixed: Chat ScreenName field was not migrated to new address book
 (bmo#1789990)
 * fixed: Creating a New Event from the Today ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP4.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~102.4.0~150200.8.85.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~102.4.0~150200.8.85.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~102.4.0~150200.8.85.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~102.4.0~150200.8.85.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~102.4.0~150200.8.85.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~102.4.0~150200.8.85.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~102.4.0~150200.8.85.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~102.4.0~150200.8.85.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~102.4.0~150200.8.85.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~102.4.0~150200.8.85.1", rls:"SLES15.0SP4"))) {
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
