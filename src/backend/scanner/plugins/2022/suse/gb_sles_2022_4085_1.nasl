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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4085.1");
  script_cve_id("CVE-2022-42927", "CVE-2022-42928", "CVE-2022-42929", "CVE-2022-42932", "CVE-2022-45403", "CVE-2022-45404", "CVE-2022-45405", "CVE-2022-45406", "CVE-2022-45408", "CVE-2022-45409", "CVE-2022-45410", "CVE-2022-45411", "CVE-2022-45412", "CVE-2022-45416", "CVE-2022-45418", "CVE-2022-45420", "CVE-2022-45421");
  script_tag(name:"creation_date", value:"2022-11-21 04:25:19 +0000 (Mon, 21 Nov 2022)");
  script_version("2022-11-21T04:25:19+0000");
  script_tag(name:"last_modification", value:"2022-11-21 04:25:19 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4085-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4085-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224085-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2022:4085-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Fixed various security issues (MFSA 2022-49, bsc#1205270):
 * CVE-2022-45403 (bmo#1762078) Service Workers might have learned size
 of cross-origin media files
 * CVE-2022-45404 (bmo#1790815) Fullscreen notification bypass
 * CVE-2022-45405 (bmo#1791314) Use-after-free in InputStream
 implementation
 * CVE-2022-45406 (bmo#1791975) Use-after-free of a JavaScript Realm
 * CVE-2022-45408 (bmo#1793829) Fullscreen notification bypass via
 windowName
 * CVE-2022-45409 (bmo#1796901) Use-after-free in Garbage Collection
 * CVE-2022-45410 (bmo#1658869) ServiceWorker-intercepted requests
 bypassed SameSite cookie policy
 * CVE-2022-45411 (bmo#1790311) Cross-Site Tracing was possible via
 non-standard override headers
 * CVE-2022-45412 (bmo#1791029) Symlinks may resolve to partially
 uninitialized buffers
 * CVE-2022-45416 (bmo#1793676) Keystroke Side-Channel Leakage
 * CVE-2022-45418 (bmo#1795815) Custom mouse cursor could have been drawn
 over browser UI
 * CVE-2022-45420 (bmo#1792643) Iframe contents could be rendered outside
 the iframe
 * CVE-2022-45421 (bmo#1767920, bmo#1789808, bmo#1794061) Memory safety
 bugs fixed in Thunderbird 102.5

Fixed various security issues: (MFSA 2022-46, bsc#1204421):
 * CVE-2022-42927 (bmo#1789128) Same-origin policy violation could have
 leaked cross-origin URLs
 * CVE-2022-42928 (bmo#1791520) Memory Corruption in JS Engine
 * CVE-2022-42929 (bmo#1789439) Denial of Service via window.print
 * CVE-2022-42932 (bmo#1789729, bmo#1791363, bmo#1792041) Memory safety
 bugs fixed in Thunderbird 102.4

Mozilla Thunderbird 102.5
 * changed: `Ctrl+N` shortcut to create new contacts from address book
 restored (bmo#1751288)
 * fixed: Account Settings UI did not update to reflect default identity
 changes (bmo#1782646)
 * fixed: New POP mail notifications were incorrectly shown for messages
 marked by filters as read or junk (bmo#1787531)
 * fixed: Connecting to an IMAP server configured to use `PREAUTH` caused
 Thunderbird to hang (bmo#1798161)
 * fixed: Error responses received in greeting header from NNTP servers
 did not display error message (bmo#1792281)
 * fixed: News messages sent using 'Send Later' failed to send after
 going back online (bmo#1794997)
 * fixed: 'Download/Sync Now...' did not completely sync all newsgroups
 before going offline (bmo#1795547)
 * fixed: Username was missing from error dialog on failed login to news
 server (bmo#1796964)
 * fixed: Thunderbird can now fetch RSS channel feeds with incomplete
 channel URL (bmo#1794775)
 * fixed: Add-on 'Contribute' button in Add-ons Manager did not work
 (bmo#1795751)
 * fixed: Help text for `/part` Matrix command was incorrect (bmo#1795578)
 * fixed: Invite Attendees dialog did not fetch free/busy info for
 attendees with encoded characters in their name (bmo#1797927)

Mozilla Thunderbird 102.4.2
 * changed: 'Address Book' ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~102.5.0~150200.8.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~102.5.0~150200.8.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~102.5.0~150200.8.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~102.5.0~150200.8.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~102.5.0~150200.8.90.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~102.5.0~150200.8.90.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~102.5.0~150200.8.90.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~102.5.0~150200.8.90.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~102.5.0~150200.8.90.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~102.5.0~150200.8.90.1", rls:"SLES15.0SP4"))) {
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
