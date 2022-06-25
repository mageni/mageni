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
  script_oid("1.3.6.1.4.1.25623.1.0.854215");
  script_version("2021-10-28T14:01:13+0000");
  script_cve_id("CVE-2021-37956", "CVE-2021-37957", "CVE-2021-37958", "CVE-2021-37959", "CVE-2021-37960", "CVE-2021-37961", "CVE-2021-37962", "CVE-2021-37963", "CVE-2021-37964", "CVE-2021-37965", "CVE-2021-37966", "CVE-2021-37967", "CVE-2021-37968", "CVE-2021-37969", "CVE-2021-37970", "CVE-2021-37971", "CVE-2021-37972", "CVE-2021-37973", "CVE-2021-37974", "CVE-2021-37975", "CVE-2021-37976", "CVE-2021-37977", "CVE-2021-37978", "CVE-2021-37979", "CVE-2021-37980");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 22:39:00 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-13 01:02:10 +0000 (Wed, 13 Oct 2021)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2021:1350-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1350-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FGCILKKE7TLKATFOFTDHZ573UHODPDOM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:1350-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 94.0.4606.81 (boo#1191463):

  * CVE-2021-37977: Use after free in Garbage Collection

  * CVE-2021-37978: Heap buffer overflow in Blink

  * CVE-2021-37979: Heap buffer overflow in WebRTC

  * CVE-2021-37980: Inappropriate implementation in Sandbox

     Chromium 94.0.4606.54 (boo#1190765):

  * CVE-2021-37956: Use after free in Offline use

  * CVE-2021-37957: Use after free in WebGPU

  * CVE-2021-37958: Inappropriate implementation in Navigation

  * CVE-2021-37959: Use after free in Task Manager

  * CVE-2021-37960: Inappropriate implementation in Blink graphics

  * CVE-2021-37961: Use after free in Tab Strip

  * CVE-2021-37962: Use after free in Performance Manager

  * CVE-2021-37963: Side-channel information leakage in DevTools

  * CVE-2021-37964: Inappropriate implementation in ChromeOS Networking

  * CVE-2021-37965: Inappropriate implementation in Background Fetch API

  * CVE-2021-37966: Inappropriate implementation in Compositing

  * CVE-2021-37967: Inappropriate implementation in Background Fetch API

  * CVE-2021-37968: Inappropriate implementation in Background Fetch API

  * CVE-2021-37969: Inappropriate implementation in Google Updater

  * CVE-2021-37970: Use after free in File System API

  * CVE-2021-37971: Incorrect security UI in Web Browser UI

  * CVE-2021-37972: Out of bounds read in libjpeg-turbo

     Chromium 94.0.4606.61 (boo#1191166):

  * CVE-2021-37973: Use after free in Portals

     Chromium 94.0.4606.71 (boo#1191204):

  * CVE-2021-37974 : Use after free in Safe Browsing

  * CVE-2021-37975 : Use after free in V8

  * CVE-2021-37976 : Information leak in core");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~94.0.4606.81~lp152.2.132.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~94.0.4606.81~lp152.2.132.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~94.0.4606.81~lp152.2.132.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~94.0.4606.81~lp152.2.132.1", rls:"openSUSELeap15.2"))) {
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