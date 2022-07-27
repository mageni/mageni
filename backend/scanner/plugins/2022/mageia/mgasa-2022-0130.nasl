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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0130");
  script_cve_id("CVE-2022-1125", "CVE-2022-1127", "CVE-2022-1128", "CVE-2022-1129", "CVE-2022-1130", "CVE-2022-1131", "CVE-2022-1132", "CVE-2022-1133", "CVE-2022-1134", "CVE-2022-1135", "CVE-2022-1136", "CVE-2022-1137", "CVE-2022-1138", "CVE-2022-1139", "CVE-2022-1141", "CVE-2022-1142", "CVE-2022-1143", "CVE-2022-1144", "CVE-2022-1145", "CVE-2022-1146");
  script_tag(name:"creation_date", value:"2022-04-07 14:17:46 +0000 (Thu, 07 Apr 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-11 10:12:33 +0000 (Mon, 11 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0130)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0130");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0130.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30222");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop_29.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0130 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use after free in Portals. (CVE-2022-1125)
Use after free in QR Code Generator. (CVE-2022-1127)
Inappropriate implementation in Web Share API. (CVE-2022-1128)
Inappropriate implementation in Full Screen Mode. (CVE-2022-1129)
Insufficient validation of untrusted input in WebOTP. (CVE-2022-1130)
Use after free in Cast UI. (CVE-2022-1131)
Inappropriate implementation in Virtual Keyboard. (CVE-2022-1132)
Use after free in WebRTC. (CVE-2022-1133)
Type Confusion in V8. (CVE-2022-1134)
Use after free in Shopping Cart. (CVE-2022-1135)
Use after free in Tab Strip. (CVE-2022-1136)
Inappropriate implementation in Extensions. (CVE-2022-1137)
Inappropriate implementation in Web Cursor. (CVE-2022-1138)
Inappropriate implementation in Background Fetch API. (CVE-2022-1139)
Use after free in File Manager. (CVE-2022-1141)
Heap buffer overflow in WebUI. (CVE-2022-1142)
Heap buffer overflow in WebUI. (CVE-2022-1143)
Use after free in WebUI. (CVE-2022-1144)
Use after free in Extensions. (CVE-2022-1145)
Inappropriate implementation in Resource Timing. (CVE-2022-1146)");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~100.0.4896.60~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~100.0.4896.60~1.mga8", rls:"MAGEIA8"))) {
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
