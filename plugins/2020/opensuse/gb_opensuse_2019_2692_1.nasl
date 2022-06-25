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
  script_oid("1.3.6.1.4.1.25623.1.0.852858");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2019-13725", "CVE-2019-13726", "CVE-2019-13727", "CVE-2019-13728",
                "CVE-2019-13729", "CVE-2019-13730", "CVE-2019-13732", "CVE-2019-13734",
                "CVE-2019-13735", "CVE-2019-13736", "CVE-2019-13737", "CVE-2019-13738",
                "CVE-2019-13739", "CVE-2019-13740", "CVE-2019-13741", "CVE-2019-13742",
                "CVE-2019-13743", "CVE-2019-13744", "CVE-2019-13745", "CVE-2019-13746",
                "CVE-2019-13747", "CVE-2019-13748", "CVE-2019-13749", "CVE-2019-13750",
                "CVE-2019-13751", "CVE-2019-13752", "CVE-2019-13753", "CVE-2019-13754",
                "CVE-2019-13755", "CVE-2019-13756", "CVE-2019-13757", "CVE-2019-13758",
                "CVE-2019-13759", "CVE-2019-13761", "CVE-2019-13762", "CVE-2019-13763",
                "CVE-2019-13764");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:37:25 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE Update for chromium openSUSE-SU-2019:2692-1 (chromium)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2019:2692_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  Chromium was updated to 79.0.3945.79 (boo#1158982)

  - CVE-2019-13725: Fixed a use after free in Bluetooth

  - CVE-2019-13726: Fixed a heap buffer overflow in password manager

  - CVE-2019-13727: Fixed an insufficient policy enforcement in WebSockets

  - CVE-2019-13728: Fixed an out of bounds write in V8

  - CVE-2019-13729: Fixed a use after free in WebSockets

  - CVE-2019-13730: Fixed a type Confusion in V8

  - CVE-2019-13732: Fixed a use after free in WebAudio

  - CVE-2019-13734: Fixed an out of bounds write in SQLite

  - CVE-2019-13735: Fixed an out of bounds write in V8

  - CVE-2019-13764: Fixed a type Confusion in V8

  - CVE-2019-13736: Fixed an integer overflow in PDFium

  - CVE-2019-13737: Fixed an insufficient policy enforcement in autocomplete

  - CVE-2019-13738: Fixed an insufficient policy enforcement in navigation

  - CVE-2019-13739: Fixed an incorrect security UI in Omnibox

  - CVE-2019-13740: Fixed an incorrect security UI in sharing

  - CVE-2019-13741: Fixed an insufficient validation of untrusted input in
  Blink

  - CVE-2019-13742: Fixed an incorrect security UI in Omnibox

  - CVE-2019-13743: Fixed an incorrect security UI in external protocol
  handling

  - CVE-2019-13744: Fixed an insufficient policy enforcement in cookies

  - CVE-2019-13745: Fixed an insufficient policy enforcement in audio

  - CVE-2019-13746: Fixed an insufficient policy enforcement in Omnibox

  - CVE-2019-13747: Fixed an uninitialized Use in rendering

  - CVE-2019-13748: Fixed an insufficient policy enforcement in developer
  tools

  - CVE-2019-13749: Fixed an incorrect security UI in Omnibox

  - CVE-2019-13750: Fixed an insufficient data validation in SQLite

  - CVE-2019-13751: Fixed an uninitialized Use in SQLite

  - CVE-2019-13752: Fixed an out of bounds read in SQLite

  - CVE-2019-13753: Fixed an out of bounds read in SQLite

  - CVE-2019-13754: Fixed an insufficient policy enforcement in extensions

  - CVE-2019-13755: Fixed an insufficient policy enforcement in extensions

  - CVE-2019-13756: Fixed an incorrect security UI in printing

  - CVE-2019-13757: Fixed an incorrect security UI in Omnibox

  - CVE-2019-13758: Fixed an insufficient policy enforcement in navigation

  - CVE-2019-13759: Fixed an incorrect security UI in interstitials

  - CVE-2019-13761: Fixed an incorrect security UI in Omnibox

  - CVE-2019-13762: Fixed an insufficient policy enforcement in downloads

  - CVE-2019-13763: Fixed an insufficient policy enforcement in payments


  Patch Instructions:

  To install this openSUSE Security U ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~79.0.3945.79~lp151.2.51.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~79.0.3945.79~lp151.2.51.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~79.0.3945.79~lp151.2.51.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~79.0.3945.79~lp151.2.51.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~79.0.3945.79~lp151.2.51.1", rls:"openSUSELeap15.1"))) {
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
