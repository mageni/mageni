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
  script_oid("1.3.6.1.4.1.25623.1.0.853843");
  script_version("2021-06-04T12:02:46+0000");
  script_cve_id("CVE-2021-21212", "CVE-2021-30521", "CVE-2021-30522", "CVE-2021-30523", "CVE-2021-30524", "CVE-2021-30525", "CVE-2021-30526", "CVE-2021-30527", "CVE-2021-30528", "CVE-2021-30529", "CVE-2021-30530", "CVE-2021-30531", "CVE-2021-30532", "CVE-2021-30533", "CVE-2021-30534", "CVE-2021-30535", "CVE-2021-30536", "CVE-2021-30537", "CVE-2021-30538", "CVE-2021-30539", "CVE-2021-30540");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-06-07 10:15:34 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-03 06:17:50 +0000 (Thu, 03 Jun 2021)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2021:0825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0825-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MJJHCREERF6N3XLSWRNBLKZ4TY5THPTY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:0825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 91.0.4472.77 (boo#1186458):

  * Support Managed configuration API for Web Applications

  * WebOTP API: cross-origin iframe support

  * CSS custom counter styles

  * Support JSON Modules

  * Clipboard: read-only files support

  * Remove webkitBeforeTextInserted &amp  webkitEditableCOntentChanged JS events

  * Honor media HTML attribute for link icon

  * Import Assertions

  * Class static initializer blocks

  * Ergonomic brand checks for private fields

  * Expose WebAssembly SIMD

  * New Feature: WebTransport

  * ES Modules for service workers (&#x27 module&#x27  type option)

  * Suggested file name and location for the File System Access API

  * adaptivePTime property for RTCRtpEncodingParameters

  * Block HTTP port 10080 - mitigation for NAT Slipstream 2.0 attack

  * Support WebSockets over HTTP/2

  * Support 103 Early Hints for Navigation

  * CVE-2021-30521: Heap buffer overflow in Autofill

  * CVE-2021-30522: Use after free in WebAudio

  * CVE-2021-30523: Use after free in WebRTC

  * CVE-2021-30524: Use after free in TabStrip

  * CVE-2021-30525: Use after free in TabGroups

  * CVE-2021-30526: Out of bounds write in TabStrip

  * CVE-2021-30527: Use after free in WebUI

  * CVE-2021-30528: Use after free in WebAuthentication

  * CVE-2021-30529: Use after free in Bookmarks

  * CVE-2021-30530: Out of bounds memory access in WebAudio

  * CVE-2021-30531: Insufficient policy enforcement in Content Security
       Policy

  * CVE-2021-30532: Insufficient policy enforcement in Content Security
       Policy

  * CVE-2021-30533: Insufficient policy enforcement in PopupBlocker

  * CVE-2021-30534: Insufficient policy enforcement in iFrameSandbox

  * CVE-2021-30535: Double free in ICU

  * CVE-2021-21212: Insufficient data validation in networking

  * CVE-2021-30536: Out of bounds read in V8

  * CVE-2021-30537: Insufficient policy enforcement in cookies

  * CVE-2021-30538: Insufficient policy enforcement in content security
       policy

  * CVE-2021-30539: Insufficient policy enforcement in content security
       policy

  * CVE-2021-30540: Incorrect security UI in payments

  * Various fixes from internal audits, fuzzing and other initiatives");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~91.0.4472.77~lp152.2.98.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~91.0.4472.77~lp152.2.98.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~91.0.4472.77~lp152.2.98.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~91.0.4472.77~lp152.2.98.1", rls:"openSUSELeap15.2"))) {
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