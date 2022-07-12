# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852598");
  script_version("2019-07-04T09:58:18+0000");
  script_cve_id("CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790",
                "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794",
                "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798",
                "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5801", "CVE-2019-5802",
                "CVE-2019-5803", "CVE-2019-5804", "CVE-2019-5805", "CVE-2019-5806",
                "CVE-2019-5807", "CVE-2019-5808", "CVE-2019-5809", "CVE-2019-5810",
                "CVE-2019-5811", "CVE-2019-5812", "CVE-2019-5813", "CVE-2019-5814",
                "CVE-2019-5815", "CVE-2019-5816", "CVE-2019-5817", "CVE-2019-5818",
                "CVE-2019-5819", "CVE-2019-5820", "CVE-2019-5821", "CVE-2019-5822",
                "CVE-2019-5823", "CVE-2019-5824", "CVE-2019-5827", "CVE-2019-5828",
                "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831", "CVE-2019-5832",
                "CVE-2019-5833", "CVE-2019-5834", "CVE-2019-5835", "CVE-2019-5836",
                "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839", "CVE-2019-5840",
                "CVE-2019-5842");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-04 09:58:18 +0000 (Thu, 04 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-06-29 02:01:15 +0000 (Sat, 29 Jun 2019)");
  script_name("openSUSE Update for chromium openSUSE-SU-2019:1666-1 (chromium)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00085.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2019:1666_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  Chromium was updated to 75.0.3770.90 (boo#1137332 boo#1138287):

  * CVE-2019-5842: Use-after-free in Blink.


  Also updated to 75.0.3770.80 boo#1137332:

  * CVE-2019-5828: Use after free in ServiceWorker

  * CVE-2019-5829: Use after free in Download Manager

  * CVE-2019-5830: Incorrectly credentialed requests in CORS

  * CVE-2019-5831: Incorrect map processing in V8

  * CVE-2019-5832: Incorrect CORS handling in XHR

  * CVE-2019-5833: Inconsistent security UI placemen

  * CVE-2019-5835: Out of bounds read in Swiftshader

  * CVE-2019-5836: Heap buffer overflow in Angle

  * CVE-2019-5837: Cross-origin resources size disclosure in Appcache

  * CVE-2019-5838: Overly permissive tab access in Extensions

  * CVE-2019-5839: Incorrect handling of certain code points in Blink

  * CVE-2019-5840: Popup blocker bypass

  * Various fixes from internal audits, fuzzing and other initiatives

  * CVE-2019-5834: URL spoof in Omnibox on iOS

  Update to 74.0.3729.169:

  * Feature fixes update only

  Update to 74.0.3729.157:

  * Various security fixes from internal audits, fuzzing and other
  initiatives

  Includes security fixes from 74.0.3729.131 (boo#1134218):

  * CVE-2019-5827: Out-of-bounds access in SQLite

  * CVE-2019-5824: Parameter passing error in media player

  Update to 74.0.3729.108 boo#1133313:

  * CVE-2019-5805: Use after free in PDFium

  * CVE-2019-5806: Integer overflow in Angle

  * CVE-2019-5807: Memory corruption in V8

  * CVE-2019-5808: Use after free in Blink

  * CVE-2019-5809: Use after free in Blink

  * CVE-2019-5810: User information disclosure in Autofill

  * CVE-2019-5811: CORS bypass in Blink

  * CVE-2019-5813: Out of bounds read in V8

  * CVE-2019-5814: CORS bypass in Blink

  * CVE-2019-5815: Heap buffer overflow in Blink

  * CVE-2019-5818: Uninitialized value in media reader

  * CVE-2019-5819: Incorrect escaping in developer tools

  * CVE-2019-5820: Integer overflow in PDFium

  * CVE-2019-5821: Integer overflow in PDFium

  * CVE-2019-5822: CORS bypass in download manager

  * CVE-2019-5823: Forced navigation from service worker

  * CVE-2019-5812: URL spoof in Omnibox on iOS

  * CVE-2019-5816: Exploit persistence extension on Android

  * CVE-2019-5817: Heap buffer overflow in Angle on Windows

  Update to 73.0.3686.103:

  * Various feature fixes

  Update to 73.0.3683.86:

  * Just feature fixes around

  - Update conditions to use system harfbuzz on TW+

  - Require java during build

  - Enable using pipewire when available

  - Rebase chromium-vaapi.patch to match up the Fedora one

  Update to 73 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~75.0.3770.90~217.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~75.0.3770.90~217.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~75.0.3770.90~217.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~75.0.3770.90~217.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~75.0.3770.90~217.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~75.0.3770.90~lp150.218.4", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~75.0.3770.90~lp150.218.4", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~75.0.3770.90~lp150.218.4", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~75.0.3770.90~lp150.218.4", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~75.0.3770.90~lp150.218.4", rls:"openSUSELeap15.0"))) {
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
