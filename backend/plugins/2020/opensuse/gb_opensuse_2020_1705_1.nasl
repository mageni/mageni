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
  script_oid("1.3.6.1.4.1.25623.1.0.853513");
  script_version("2020-10-29T06:27:27+0000");
  script_cve_id("CVE-2020-15967", "CVE-2020-15968", "CVE-2020-15969", "CVE-2020-15970", "CVE-2020-15971", "CVE-2020-15972", "CVE-2020-15973", "CVE-2020-15974", "CVE-2020-15975", "CVE-2020-15976", "CVE-2020-15977", "CVE-2020-15978", "CVE-2020-15979", "CVE-2020-15980", "CVE-2020-15981", "CVE-2020-15982", "CVE-2020-15983", "CVE-2020-15984", "CVE-2020-15985", "CVE-2020-15986", "CVE-2020-15987", "CVE-2020-15988", "CVE-2020-15989", "CVE-2020-15990", "CVE-2020-15991", "CVE-2020-15992", "CVE-2020-6557");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-10-29 11:17:52 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-23 03:01:08 +0000 (Fri, 23 Oct 2020)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2020:1705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1705-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00046.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:1705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  - chromium was updated to 86.0.4240.75 (boo#1177408):

  - CVE-2020-15967: Fixed Use after free in payments.

  - CVE-2020-15968: Fixed Use after free in Blink.

  - CVE-2020-15969: Fixed Use after free in WebRTC.

  - CVE-2020-15970: Fixed Use after free in NFC.

  - CVE-2020-15971: Fixed Use after free in printing.

  - CVE-2020-15972: Fixed Use after free in audio.

  - CVE-2020-15990: Fixed Use after free in autofill.

  - CVE-2020-15991: Fixed Use after free in password manager.

  - CVE-2020-15973: Fixed Insufficient policy enforcement in extensions.

  - CVE-2020-15974: Fixed Integer overflow in Blink.

  - CVE-2020-15975: Fixed Integer overflow in SwiftShader.

  - CVE-2020-15976: Fixed Use after free in WebXR.

  - CVE-2020-6557: Fixed Inappropriate implementation in networking.

  - CVE-2020-15977: Fixed Insufficient data validation in dialogs.

  - CVE-2020-15978: Fixed Insufficient data validation in navigation.

  - CVE-2020-15979: Fixed Inappropriate implementation in V8.

  - CVE-2020-15980: Fixed Insufficient policy enforcement in Intents.

  - CVE-2020-15981: Fixed Out of bounds read in audio.

  - CVE-2020-15982: Fixed Side-channel information leakage in cache.

  - CVE-2020-15983: Fixed Insufficient data validation in webUI.

  - CVE-2020-15984: Fixed Insufficient policy enforcement in Omnibox.

  - CVE-2020-15985: Fixed Inappropriate implementation in Blink.

  - CVE-2020-15986: Fixed Integer overflow in media.

  - CVE-2020-15987: Fixed Use after free in WebRTC.

  - CVE-2020-15992: Fixed Insufficient policy enforcement in networking.

  - CVE-2020-15988: Fixed Insufficient policy enforcement in downloads.

  - CVE-2020-15989: Fixed Uninitialized Use in PDFium.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1705=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1705=1");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~86.0.4240.75~lp152.2.39.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~86.0.4240.75~lp152.2.39.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~86.0.4240.75~lp152.2.39.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~86.0.4240.75~lp152.2.39.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn", rpm:"gn~0.1807~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debuginfo", rpm:"gn-debuginfo~0.1807~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debugsource", rpm:"gn-debugsource~0.1807~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~86.0.4240.75~lp151.2.144.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~86.0.4240.75~lp151.2.144.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~86.0.4240.75~lp151.2.144.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~86.0.4240.75~lp151.2.144.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn", rpm:"gn~0.1807~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debuginfo", rpm:"gn-debuginfo~0.1807~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debugsource", rpm:"gn-debugsource~0.1807~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
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