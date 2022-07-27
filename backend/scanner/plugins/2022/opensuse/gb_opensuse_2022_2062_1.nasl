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
  script_oid("1.3.6.1.4.1.25623.1.0.854739");
  script_version("2022-06-15T04:37:18+0000");
  script_cve_id("CVE-2022-1529", "CVE-2022-1802", "CVE-2022-1834", "CVE-2022-31736", "CVE-2022-31737", "CVE-2022-31738", "CVE-2022-31739", "CVE-2022-31740", "CVE-2022-31741", "CVE-2022-31742", "CVE-2022-31747");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-06-15 10:13:29 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-14 01:02:25 +0000 (Tue, 14 Jun 2022)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (SUSE-SU-2022:2062-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2062-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3BUBGLROYPBOSCUZLR2QFWLWZP6WMIS2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the SUSE-SU-2022:2062-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:
  Update to Mozilla Thunderbird 91.9.1
  MFSA 2022-19 (bsc#1199768):

  - CVE-2022-1802: Prototype pollution in Top-Level Await implementation
       (bmo#1770137).

  - CVE-2022-1529: Untrusted input used in JavaScript object indexing,
       leading to prototype pollution (bmo#1770048).
  Update to Mozilla Thunderbird 91.10
  MFSA 2022-22 (bsc#1200027):

  - CVE-2022-31736: Cross-Origin resource's length leaked (bmo#1735923)

  - CVE-2022-31737: Heap buffer overflow in WebGL (bmo#1743767)

  - CVE-2022-31738: Browser window spoof using fullscreen mode (bmo#1756388)

  - CVE-2022-31739: Attacker-influenced path traversal when saving
       downloaded files (bmo#1765049)

  - CVE-2022-31740: Register allocation problem in WASM on arm64
       (bmo#1766806)

  - CVE-2022-31741: Uninitialized variable leads to invalid memory read
       (bmo#1767590)

  - CVE-2022-1834: Braille space character caused incorrect sender email to
       be  shown for a digitally signed email (bmo#1767816)

  - CVE-2022-31742: Querying a WebAuthn token with a large number of
       allowCredential entries may have leaked cross-origin information
       (bmo#1730434)

  - CVE-2022-31747: Memory safety bugs fixed in Thunderbird 91.10
       (bmo#1760765, bmo#1765610, bmo#1766283, bmo#1767365, bmo#1768559,
       bmo#1768734)");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~91.10.0~150200.8.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~91.10.0~150200.8.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~91.10.0~150200.8.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~91.10.0~150200.8.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~91.10.0~150200.8.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~91.10.0~150200.8.73.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~91.10.0~150200.8.73.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~91.10.0~150200.8.73.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~91.10.0~150200.8.73.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~91.10.0~150200.8.73.1", rls:"openSUSELeap15.3"))) {
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