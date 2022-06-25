# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.853115");
  script_version("2020-04-21T09:23:28+0000");
  script_cve_id("CVE-2020-6423", "CVE-2020-6430", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433", "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437", "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441", "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445", "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448", "CVE-2020-6450", "CVE-2020-6451", "CVE-2020-6452", "CVE-2020-6454", "CVE-2020-6455", "CVE-2020-6456");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-21 10:11:05 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-16 03:00:51 +0000 (Thu, 16 Apr 2020)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2020:0519-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00024.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:0519-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  Chromium was updated to 81.0.4044.92 boo#1168911:

  * CVE-2020-6454: Use after free in extensions

  * CVE-2020-6423: Use after free in audio

  * CVE-2020-6455: Out of bounds read in WebSQL

  * CVE-2020-6430: Type Confusion in V8

  * CVE-2020-6456: Insufficient validation of untrusted input in clipboard

  * CVE-2020-6431: Insufficient policy enforcement in full screen

  * CVE-2020-6432: Insufficient policy enforcement in navigations

  * CVE-2020-6433: Insufficient policy enforcement in extensions

  * CVE-2020-6434: Use after free in devtools

  * CVE-2020-6435: Insufficient policy enforcement in extensions

  * CVE-2020-6436: Use after free in window management

  * CVE-2020-6437: Inappropriate implementation in WebView

  * CVE-2020-6438: Insufficient policy enforcement in extensions

  * CVE-2020-6439: Insufficient policy enforcement in navigations

  * CVE-2020-6440: Inappropriate implementation in extensions

  * CVE-2020-6441: Insufficient policy enforcement in omnibox

  * CVE-2020-6442: Inappropriate implementation in cache

  * CVE-2020-6443: Insufficient data validation in developer tools

  * CVE-2020-6444: Uninitialized Use in WebRTC

  * CVE-2020-6445: Insufficient policy enforcement in trusted types

  * CVE-2020-6446: Insufficient policy enforcement in trusted types

  * CVE-2020-6447: Inappropriate implementation in developer tools

  * CVE-2020-6448: Use after free in V8

  Chromium was updated to 80.0.3987.162 boo#1168421:

  * CVE-2020-6450: Use after free in WebAudio.

  * CVE-2020-6451: Use after free in WebAudio.

  * CVE-2020-6452: Heap buffer overflow in media.

  - Use a symbolic icon for GNOME


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-519=1");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~81.0.4044.92~lp151.2.77.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~81.0.4044.92~lp151.2.77.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~81.0.4044.92~lp151.2.77.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~81.0.4044.92~lp151.2.77.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~81.0.4044.92~lp151.2.77.1", rls:"openSUSELeap15.1"))) {
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