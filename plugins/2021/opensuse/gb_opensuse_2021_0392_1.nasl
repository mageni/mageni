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
  script_oid("1.3.6.1.4.1.25623.1.0.853586");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2020-27844", "CVE-2021-21149", "CVE-2021-21150", "CVE-2021-21151", "CVE-2021-21152", "CVE-2021-21153", "CVE-2021-21154", "CVE-2021-21155", "CVE-2021-21156", "CVE-2021-21157", "CVE-2021-21159", "CVE-2021-21160", "CVE-2021-21161", "CVE-2021-21162", "CVE-2021-21163", "CVE-2021-21164", "CVE-2021-21165", "CVE-2021-21166", "CVE-2021-21167", "CVE-2021-21168", "CVE-2021-21169", "CVE-2021-21170", "CVE-2021-21171", "CVE-2021-21172", "CVE-2021-21173", "CVE-2021-21174", "CVE-2021-21175", "CVE-2021-21176", "CVE-2021-21177", "CVE-2021-21178", "CVE-2021-21179", "CVE-2021-21180", "CVE-2021-21181", "CVE-2021-21182", "CVE-2021-21183", "CVE-2021-21184", "CVE-2021-21185", "CVE-2021-21186", "CVE-2021-21187", "CVE-2021-21188", "CVE-2021-21189", "CVE-2021-21190");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:55:31 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2021:0392-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0392-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/S66YPMC4VLRMKQGSTL3XFAVYDCVH7ADY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:0392-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Update to 89.0.4389.72 (boo#1182358, boo#1182960):

  - CVE-2021-21159: Heap buffer overflow in TabStrip.

  - CVE-2021-21160: Heap buffer overflow in WebAudio.

  - CVE-2021-21161: Heap buffer overflow in TabStrip.

  - CVE-2021-21162: Use after free in WebRTC.

  - CVE-2021-21163: Insufficient data validation in Reader Mode.

  - CVE-2021-21164: Insufficient data validation in Chrome for iOS.

  - CVE-2021-21165: Object lifecycle issue in audio.

  - CVE-2021-21166: Object lifecycle issue in audio.

  - CVE-2021-21167: Use after free in bookmarks.

  - CVE-2021-21168: Insufficient policy enforcement in appcache.

  - CVE-2021-21169: Out of bounds memory access in V8.

  - CVE-2021-21170: Incorrect security UI in Loader.

  - CVE-2021-21171: Incorrect security UI in TabStrip and Navigation.

  - CVE-2021-21172: Insufficient policy enforcement in File System API.

  - CVE-2021-21173: Side-channel information leakage in Network Internals.

  - CVE-2021-21174: Inappropriate implementation in Referrer.

  - CVE-2021-21175: Inappropriate implementation in Site isolation.

  - CVE-2021-21176: Inappropriate implementation in full screen mode.

  - CVE-2021-21177: Insufficient policy enforcement in Autofill.

  - CVE-2021-21178: Inappropriate implementation in Compositing.

  - CVE-2021-21179: Use after free in Network Internals.

  - CVE-2021-21180: Use after free in tab search.

  - CVE-2020-27844: Heap buffer overflow in OpenJPEG.

  - CVE-2021-21181: Side-channel information leakage in autofill.

  - CVE-2021-21182: Insufficient policy enforcement in navigations.

  - CVE-2021-21183: Inappropriate implementation in performance APIs.

  - CVE-2021-21184: Inappropriate implementation in performance APIs.

  - CVE-2021-21185: Insufficient policy enforcement in extensions.

  - CVE-2021-21186: Insufficient policy enforcement in QR scanning.

  - CVE-2021-21187: Insufficient data validation in URL formatting.

  - CVE-2021-21188: Use after free in Blink.

  - CVE-2021-21189: Insufficient policy enforcement in payments.

  - CVE-2021-21190: Uninitialized Use in PDFium.

  - CVE-2021-21149: Stack overflow in Data Transfer.

  - CVE-2021-21150: Use after free in Downloads.

  - CVE-2021-21151: Use after free in Payments.

  - CVE-2021-21152: Heap buffer overflow in Media.

  - CVE-2021-21153: Stack overflow in GPU Process.

  - CVE-2021-21154: Heap buffer overflow in Tab Strip.

  - CVE-2021-21155: Heap buffer overflow in Tab Strip.

  - CVE-2021-21156:  ...

  Description truncated. Please see the references for more information.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~89.0.4389.72~lp152.2.77.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~89.0.4389.72~lp152.2.77.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~89.0.4389.72~lp152.2.77.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~89.0.4389.72~lp152.2.77.1", rls:"openSUSELeap15.2"))) {
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