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
  script_oid("1.3.6.1.4.1.25623.1.0.854373");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2021-38005", "CVE-2021-38006", "CVE-2021-38007", "CVE-2021-38008", "CVE-2021-38009", "CVE-2021-38010", "CVE-2021-38011", "CVE-2021-38012", "CVE-2021-38013", "CVE-2021-38014", "CVE-2021-38015", "CVE-2021-38016", "CVE-2021-38017", "CVE-2021-38018", "CVE-2021-38019", "CVE-2021-38020", "CVE-2021-38021", "CVE-2021-38022", "CVE-2021-4052", "CVE-2021-4053", "CVE-2021-4054", "CVE-2021-4055", "CVE-2021-4056", "CVE-2021-4057", "CVE-2021-4058", "CVE-2021-4059", "CVE-2021-4061", "CVE-2021-4062", "CVE-2021-4063", "CVE-2021-4064", "CVE-2021-4065", "CVE-2021-4066", "CVE-2021-4067", "CVE-2021-4068", "CVE-2021-4078", "CVE-2021-4079", "CVE-2021-4098", "CVE-2021-4099", "CVE-2021-4100", "CVE-2021-4101", "CVE-2021-4102");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 06:33:05 +0000 (Tue, 01 Feb 2022)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2021:1632-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1632-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DUJZLITO4GTLR5FP75FBCLDYZMUY2AFI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:1632-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:
  Chromium 96.0.4664.110 (boo#1193713):

  * CVE-2021-4098: Insufficient data validation in Mojo

  * CVE-2021-4099: Use after free in Swiftshader

  * CVE-2021-4100: Object lifecycle issue in ANGLE

  * CVE-2021-4101: Heap buffer overflow in Swiftshader

  * CVE-2021-4102: Use after free in V8
  Lord of the Browsers: The Two Compilers:

  * Go back to GCC

  * GCC: LTO removes needed assembly symbols

  * Clang: issues with libstdc++
  Chromium 96.0.4664.93 (boo#1193519):

  * CVE-2021-4052: Use after free in web apps

  * CVE-2021-4053: Use after free in UI

  * CVE-2021-4079: Out of bounds write in WebRTC

  * CVE-2021-4054: Incorrect security UI in autofill

  * CVE-2021-4078: Type confusion in V8

  * CVE-2021-4055: Heap buffer overflow in extensions

  * CVE-2021-4056: Type Confusion in loader

  * CVE-2021-4057: Use after free in file API

  * CVE-2021-4058: Heap buffer overflow in ANGLE

  * CVE-2021-4059: Insufficient data validation in loader

  * CVE-2021-4061: Type Confusion in V8

  * CVE-2021-4062: Heap buffer overflow in BFCache

  * CVE-2021-4063: Use after free in developer tools

  * CVE-2021-4064: Use after free in screen capture

  * CVE-2021-4065: Use after free in autofill

  * CVE-2021-4066: Integer underflow in ANGLE

  * CVE-2021-4067: Use after free in window manager

  * CVE-2021-4068: Insufficient validation of untrusted input in new tab page
  Chromium 96.0.4664.45 (boo#1192734):

  * CVE-2021-38007: Type Confusion in V8

  * CVE-2021-38008: Use after free in media

  * CVE-2021-38009: Inappropriate implementation in cache

  * CVE-2021-38006: Use after free in storage foundation

  * CVE-2021-38005: Use after free in loader

  * CVE-2021-38010: Inappropriate implementation in service workers

  * CVE-2021-38011: Use after free in storage foundation

  * CVE-2021-38012: Type Confusion in V8

  * CVE-2021-38013: Heap buffer overflow in fingerprint recognition

  * CVE-2021-38014: Out of bounds write in Swiftshader

  * CVE-2021-38015: Inappropriate implementation in input

  * CVE-2021-38016: Insufficient policy enforcement in background fetch

  * CVE-2021-38017: Insufficient policy enforcement in iframe sandbox

  * CVE-2021-38018: Inappropriate implementation in navigation

  * CVE-2021-38019: Insufficient policy enforcement in CORS

  * CVE-2021-38020: Insufficient policy enforcement in contacts picker

  * CVE-2021-38021: Inappropriate implementation in referrer

  * CVE-2021-38022: Inappropriate implementation in WebAuthentication");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~96.0.4664.110~lp152.2.143.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~96.0.4664.110~lp152.2.143.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~96.0.4664.110~lp152.2.143.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~96.0.4664.110~lp152.2.143.1", rls:"openSUSELeap15.2"))) {
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