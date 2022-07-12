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
  script_oid("1.3.6.1.4.1.25623.1.0.853297");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2020-6510", "CVE-2020-6511", "CVE-2020-6512", "CVE-2020-6513", "CVE-2020-6514", "CVE-2020-6515", "CVE-2020-6516", "CVE-2020-6517", "CVE-2020-6518", "CVE-2020-6519", "CVE-2020-6520", "CVE-2020-6521", "CVE-2020-6522", "CVE-2020-6523", "CVE-2020-6524", "CVE-2020-6525", "CVE-2020-6526", "CVE-2020-6527", "CVE-2020-6528", "CVE-2020-6529", "CVE-2020-6530", "CVE-2020-6531", "CVE-2020-6533", "CVE-2020-6534", "CVE-2020-6535", "CVE-2020-6536");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-21 03:02:32 +0000 (Tue, 21 Jul 2020)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2020:1020-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1020-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00051.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:1020-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  - Update to 84.0.4147.89 boo#1174189:

  * Critical CVE-2020-6510: Heap buffer overflow in background fetch.

  * High CVE-2020-6511: Side-channel information leakage in content
  security policy.

  * High CVE-2020-6512: Type Confusion in V8.

  * High CVE-2020-6513: Heap buffer overflow in PDFium.

  * High CVE-2020-6514: Inappropriate implementation in WebRTC.

  * High CVE-2020-6515: Use after free in tab strip.

  * High CVE-2020-6516: Policy bypass in CORS.

  * High CVE-2020-6517: Heap buffer overflow in history.

  * Medium CVE-2020-6518: Use after free in developer tools.

  * Medium CVE-2020-6519: Policy bypass in CSP.

  * Medium CVE-2020-6520: Heap buffer overflow in Skia.

  * Medium CVE-2020-6521: Side-channel information leakage in autofill.

  * Medium CVE-2020-6522: Inappropriate implementation in external
  protocol handlers.

  * Medium CVE-2020-6523: Out of bounds write in Skia.

  * Medium CVE-2020-6524: Heap buffer overflow in WebAudio.

  * Medium CVE-2020-6525: Heap buffer overflow in Skia.

  * Low CVE-2020-6526: Inappropriate implementation in iframe sandbox.

  * Low CVE-2020-6527: Insufficient policy enforcement in CSP.

  * Low CVE-2020-6528: Incorrect security UI in basic auth.

  * Low CVE-2020-6529: Inappropriate implementation in WebRTC.

  * Low CVE-2020-6530: Out of bounds memory access in developer tools.

  * Low CVE-2020-6531: Side-channel information leakage in scroll to text.

  * Low CVE-2020-6533: Type Confusion in V8.

  * Low CVE-2020-6534: Heap buffer overflow in WebRTC.

  * Low CVE-2020-6535: Insufficient data validation in WebUI.

  * Low CVE-2020-6536: Incorrect security UI in PWAs.

  - Use bundled xcb-proto as we need to generate py2 bindings

  - Try to fix non-wayland build for Leap builds


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1020=1");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~84.0.4147.89~lp152.2.6.2", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~84.0.4147.89~lp152.2.6.2", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~84.0.4147.89~lp152.2.6.2", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~84.0.4147.89~lp152.2.6.2", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~84.0.4147.89~lp152.2.6.2", rls:"openSUSELeap15.2"))) {
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