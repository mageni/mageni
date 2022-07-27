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
  script_oid("1.3.6.1.4.1.25623.1.0.854180");
  script_version("2021-09-24T08:01:25+0000");
  script_cve_id("CVE-2021-30606", "CVE-2021-30607", "CVE-2021-30608", "CVE-2021-30609", "CVE-2021-30610", "CVE-2021-30611", "CVE-2021-30612", "CVE-2021-30613", "CVE-2021-30614", "CVE-2021-30615", "CVE-2021-30616", "CVE-2021-30617", "CVE-2021-30618", "CVE-2021-30619", "CVE-2021-30620", "CVE-2021-30621", "CVE-2021-30622", "CVE-2021-30623", "CVE-2021-30624", "CVE-2021-30625", "CVE-2021-30626", "CVE-2021-30627", "CVE-2021-30628", "CVE-2021-30629", "CVE-2021-30630", "CVE-2021-30631", "CVE-2021-30632", "CVE-2021-30633");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-24 11:43:38 +0000 (Fri, 24 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-07 21:58:00 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-23 01:01:49 +0000 (Thu, 23 Sep 2021)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2021:1303-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1303-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XKFA6UOYGKCDBHHUW6MA56YT5KIDLCNF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:1303-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 93.0.4577.63 (boo#1190096):

  * CVE-2021-30606: Use after free in Blink

  * CVE-2021-30607: Use after free in Permissions

  * CVE-2021-30608: Use after free in Web Share

  * CVE-2021-30609: Use after free in Sign-In

  * CVE-2021-30610: Use after free in Extensions API

  * CVE-2021-30611: Use after free in WebRTC

  * CVE-2021-30612: Use after free in WebRTC

  * CVE-2021-30613: Use after free in Base internals

  * CVE-2021-30614: Heap buffer overflow in TabStrip

  * CVE-2021-30615: Cross-origin data leak in Navigation

  * CVE-2021-30616: Use after free in Media

  * CVE-2021-30617: Policy bypass in Blink

  * CVE-2021-30618: Inappropriate implementation in DevTools

  * CVE-2021-30619: UI Spoofing in Autofill

  * CVE-2021-30620: Insufficient policy enforcement in Blink

  * CVE-2021-30621: UI Spoofing in Autofill

  * CVE-2021-30622: Use after free in WebApp Installs

  * CVE-2021-30623: Use after free in Bookmarks

  * CVE-2021-30624: Use after free in Autofill

     Chromium 93.0.4577.82 (boo#1190476):

  * CVE-2021-30625: Use after free in Selection API

  * CVE-2021-30626: Out of bounds memory access in ANGLE

  * CVE-2021-30627: Type Confusion in Blink layout

  * CVE-2021-30628: Stack buffer overflow in ANGLE

  * CVE-2021-30629: Use after free in Permissions

  * CVE-2021-30630: Inappropriate implementation in Blink

  * CVE-2021-30631: Type Confusion in Blink layout

  * CVE-2021-30632: Out of bounds write in V8

  * CVE-2021-30633: Use after free in Indexed DB API");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~93.0.4577.82~lp152.2.125.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~93.0.4577.82~lp152.2.125.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~93.0.4577.82~lp152.2.125.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~93.0.4577.82~lp152.2.125.1", rls:"openSUSELeap15.2"))) {
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