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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0158");
  script_cve_id("CVE-2022-1477", "CVE-2022-1478", "CVE-2022-1479", "CVE-2022-1481", "CVE-2022-1482", "CVE-2022-1483", "CVE-2022-1484", "CVE-2022-1485", "CVE-2022-1486", "CVE-2022-1487", "CVE-2022-1488", "CVE-2022-1489", "CVE-2022-1490", "CVE-2022-1491", "CVE-2022-1492", "CVE-2022-1493", "CVE-2022-1494", "CVE-2022-1495", "CVE-2022-1496", "CVE-2022-1497", "CVE-2022-1498", "CVE-2022-1499", "CVE-2022-1500", "CVE-2022-1501");
  script_tag(name:"creation_date", value:"2022-05-03 08:04:45 +0000 (Tue, 03 May 2022)");
  script_version("2022-05-03T08:04:45+0000");
  script_tag(name:"last_modification", value:"2022-05-04 10:05:48 +0000 (Wed, 04 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0158)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0158");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0158.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30350");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/04/stable-channel-update-for-desktop_26.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0158 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use after free in Vulkan. (CVE-2022-1477)
Use after free in SwiftShader. (CVE-2022-1478)
Use after free in ANGLE. (CVE-2022-1479)
Use after free in Sharing. (CVE-2022-1481)
Inappropriate implementation in WebGL. (CVE-2022-1482)
Heap buffer overflow in WebGPU. (CVE-2022-1483)
Heap buffer overflow in Web UI Settings. (CVE-2022-1484)
Use after free in File System API. (CVE-2022-1485)
Type Confusion in V8. (CVE-2022-1486)
Use after free in Ozone. (CVE-2022-1487)
Inappropriate implementation in Extensions API. (CVE-2022-1488)
Out of bounds memory access in UI Shelf. (CVE-2022-1489)
Use after free in Browser Switcher. (CVE-2022-1490)
Use after free in Bookmarks. (CVE-2022-1491)
Insufficient data validation in Blink Editing. (CVE-2022-1492)
Use after free in Dev Tools. (CVE-2022-1493)
Insufficient data validation in Trusted Types. (CVE-2022-1494)
Incorrect security UI in Downloads. (CVE-2022-1495)
Use after free in File Manager. (CVE-2022-1496)
Inappropriate implementation in Input. (CVE-2022-1497)
Inappropriate implementation in HTML Parser. (CVE-2022-1498)
Inappropriate implementation in WebAuthentication. (CVE-2022-1499)
Insufficient data validation in Dev Tools. (CVE-2022-1500)
Inappropriate implementation in iframe. (CVE-2022-1501)");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~101.0.4951.41~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~101.0.4951.41~1.mga8", rls:"MAGEIA8"))) {
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
