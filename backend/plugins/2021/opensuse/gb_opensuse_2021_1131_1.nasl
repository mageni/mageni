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
  script_oid("1.3.6.1.4.1.25623.1.0.854056");
  script_version("2021-08-24T09:58:36+0000");
  script_cve_id("CVE-2021-30565", "CVE-2021-30566", "CVE-2021-30567", "CVE-2021-30568", "CVE-2021-30569", "CVE-2021-30571", "CVE-2021-30572", "CVE-2021-30573", "CVE-2021-30574", "CVE-2021-30575", "CVE-2021-30576", "CVE-2021-30577", "CVE-2021-30578", "CVE-2021-30579", "CVE-2021-30581", "CVE-2021-30582", "CVE-2021-30584", "CVE-2021-30585", "CVE-2021-30588", "CVE-2021-30589", "CVE-2021-30590", "CVE-2021-30591", "CVE-2021-30592", "CVE-2021-30593", "CVE-2021-30594", "CVE-2021-30596", "CVE-2021-30597");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-11 03:02:29 +0000 (Wed, 11 Aug 2021)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2021:1131-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1131-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QMTT3WQIVTBT7PZKT6YDJXEYNVRRJDO2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:1131-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 92.0.4515.131 (boo#1189006)

  * CVE-2021-30590: Heap buffer overflow in Bookmarks

  * CVE-2021-30591: Use after free in File System API

  * CVE-2021-30592: Out of bounds write in Tab Groups

  * CVE-2021-30593: Out of bounds read in Tab Strip

  * CVE-2021-30594: Use after free in Page Info UI

  * CVE-2021-30596: Incorrect security UI in Navigation

  * CVE-2021-30597: Use after free in Browser UI

     Chromium 92.0.4515.107 (boo#1188590)

  * CVE-2021-30565: Out of bounds write in Tab Groups

  * CVE-2021-30566: Stack buffer overflow in Printing

  * CVE-2021-30567: Use after free in DevTools

  * CVE-2021-30568: Heap buffer overflow in WebGL

  * CVE-2021-30569: Use after free in sqlite

  * CVE-2021-30571: Insufficient policy enforcement in DevTools

  * CVE-2021-30572: Use after free in Autofill

  * CVE-2021-30573: Use after free in GPU

  * CVE-2021-30574: Use after free in protocol handling

  * CVE-2021-30575: Out of bounds read in Autofill

  * CVE-2021-30576: Use after free in DevTools

  * CVE-2021-30577: Insufficient policy enforcement in Installer

  * CVE-2021-30578: Uninitialized Use in Media

  * CVE-2021-30579: Use after free in UI framework

  * CVE-2021-30581: Use after free in DevTools

  * CVE-2021-30582: Inappropriate implementation in Animation

  * CVE-2021-30584: Incorrect security UI in Downloads

  * CVE-2021-30585: Use after free in sensor handling

  * CVE-2021-30588: Type Confusion in V8

  * CVE-2021-30589: Insufficient validation of untrusted input in Sharing");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~92.0.4515.131~lp152.2.116.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~92.0.4515.131~lp152.2.116.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~92.0.4515.131~lp152.2.116.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~92.0.4515.131~lp152.2.116.1", rls:"openSUSELeap15.2"))) {
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