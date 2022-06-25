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
  script_oid("1.3.6.1.4.1.25623.1.0.853030");
  script_version("2020-02-14T06:25:11+0000");
  script_cve_id("CVE-2019-18197", "CVE-2019-19880", "CVE-2019-19923", "CVE-2019-19925", "CVE-2019-19926", "CVE-2020-6381", "CVE-2020-6382", "CVE-2020-6385", "CVE-2020-6387", "CVE-2020-6388", "CVE-2020-6389", "CVE-2020-6390", "CVE-2020-6391", "CVE-2020-6392", "CVE-2020-6393", "CVE-2020-6394", "CVE-2020-6395", "CVE-2020-6396", "CVE-2020-6397", "CVE-2020-6398", "CVE-2020-6399", "CVE-2020-6400", "CVE-2020-6401", "CVE-2020-6402", "CVE-2020-6403", "CVE-2020-6404", "CVE-2020-6405", "CVE-2020-6406", "CVE-2020-6408", "CVE-2020-6409", "CVE-2020-6410", "CVE-2020-6411", "CVE-2020-6412", "CVE-2020-6413", "CVE-2020-6414", "CVE-2020-6415", "CVE-2020-6416", "CVE-2020-6417");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-02-14 06:25:11 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-10 04:00:44 +0000 (Mon, 10 Feb 2020)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2020:0189-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00010.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:0189-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  Chromium was updated to version 80.0.3987.87 (boo#1162833).

  Security issues fixed:

  - CVE-2020-6381: Integer overflow in JavaScript (boo#1162833).

  - CVE-2020-6382: Type Confusion in JavaScript (boo#1162833).

  - CVE-2019-18197: Multiple vulnerabilities in XML (boo#1162833).

  - CVE-2019-19926: Inappropriate implementation in SQLite (boo#1162833).

  - CVE-2020-6385: Insufficient policy enforcement in storage (boo#1162833).

  - CVE-2019-19880, CVE-2019-19925: Multiple vulnerabilities in SQLite
  (boo#1162833).

  - CVE-2020-6387: Out of bounds write in WebRTC (boo#1162833).

  - CVE-2020-6388: Out of bounds memory access in WebAudio (boo#1162833).

  - CVE-2020-6389: Out of bounds write in WebRTC (boo#1162833).

  - CVE-2020-6390: Out of bounds memory access in streams (boo#1162833).

  - CVE-2020-6391: Insufficient validation of untrusted input in Blink
  (boo#1162833).

  - CVE-2020-6392: Insufficient policy enforcement in extensions
  (boo#1162833).

  - CVE-2020-6393: Insufficient policy enforcement in Blink (boo#1162833).

  - CVE-2020-6394: Insufficient policy enforcement in Blink (boo#1162833).

  - CVE-2020-6395: Out of bounds read in JavaScript (boo#1162833).

  - CVE-2020-6396: Inappropriate implementation in Skia (boo#1162833).

  - CVE-2020-6397: Incorrect security UI in sharing (boo#1162833).

  - CVE-2020-6398: Uninitialized use in PDFium (boo#1162833).

  - CVE-2020-6399: Insufficient policy enforcement in AppCache (boo#1162833).

  - CVE-2020-6400: Inappropriate implementation in CORS (boo#1162833).

  - CVE-2020-6401: Insufficient validation of untrusted input in Omnibox
  (boo#1162833).

  - CVE-2020-6402: Insufficient policy enforcement in downloads
  (boo#1162833).

  - CVE-2020-6403: Incorrect security UI in Omnibox (boo#1162833).

  - CVE-2020-6404: Inappropriate implementation in Blink (boo#1162833).

  - CVE-2020-6405: Out of bounds read in SQLite (boo#1162833).

  - CVE-2020-6406: Use after free in audio (boo#1162833).

  - CVE-2019-19923: Out of bounds memory access in SQLite (boo#1162833).

  - CVE-2020-6408: Insufficient policy enforcement in CORS (boo#1162833).

  - CVE-2020-6409: Inappropriate implementation in Omnibox (boo#1162833).

  - CVE-2020-6410: Insufficient policy enforcement in navigation
  (boo#1162833).

  - CVE-2020-6411: Insufficient validation of untrusted input in Omnibox
  (boo#1162833).

  - CVE-2020-6412: Insufficient validation of untrusted input in Omnibox
  (boo#1162833).

  - CVE-2020-6413: Inappropriate implementation in Blink (boo#1162833).

  - CVE-2020-6414: Insufficient policy enforcement in Safe ...

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~80.0.3987.87~lp151.2.63.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~80.0.3987.87~lp151.2.63.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~80.0.3987.87~lp151.2.63.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~80.0.3987.87~lp151.2.63.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~80.0.3987.87~lp151.2.63.1", rls:"openSUSELeap15.1"))) {
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