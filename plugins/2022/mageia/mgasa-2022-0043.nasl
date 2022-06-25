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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0043");
  script_cve_id("CVE-2022-0096", "CVE-2022-0097", "CVE-2022-0098", "CVE-2022-0099", "CVE-2022-0100", "CVE-2022-0101", "CVE-2022-0102", "CVE-2022-0103", "CVE-2022-0104", "CVE-2022-0105", "CVE-2022-0106", "CVE-2022-0107", "CVE-2022-0108", "CVE-2022-0109", "CVE-2022-0110", "CVE-2022-0111", "CVE-2022-0112", "CVE-2022-0113", "CVE-2022-0114", "CVE-2022-0115", "CVE-2022-0116", "CVE-2022-0117", "CVE-2022-0118", "CVE-2022-0120", "CVE-2022-0289", "CVE-2022-0290", "CVE-2022-0291", "CVE-2022-0292", "CVE-2022-0293", "CVE-2022-0294", "CVE-2022-0295", "CVE-2022-0296", "CVE-2022-0297", "CVE-2022-0298", "CVE-2022-0300", "CVE-2022-0301", "CVE-2022-0302", "CVE-2022-0304", "CVE-2022-0305", "CVE-2022-0306", "CVE-2022-0307", "CVE-2022-0308", "CVE-2022-0309", "CVE-2022-0310", "CVE-2022-0311", "CVE-2022-0337");
  script_tag(name:"creation_date", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");
  script_version("2022-02-09T07:40:33+0000");
  script_tag(name:"last_modification", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0043)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0043");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0043.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29846");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/01/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/01/stable-channel-update-for-desktop_19.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0043 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-0096: Use after free in Storage.
CVE-2022-0097: Inappropriate implementation in DevTools.
CVE-2022-0098: Use after free in Screen Capture.
CVE-2022-0099: Use after free in Sign-in.
CVE-2022-0100: Heap buffer overflow in Media streams API.
CVE-2022-0101: Heap buffer overflow in Bookmarks.
CVE-2022-0102: Type Confusion in V8.
CVE-2022-0103: Use after free in SwiftShader.
CVE-2022-0104: Heap buffer overflow in ANGLE.
CVE-2022-0105: Use after free in PDF.
CVE-2022-0106: Use after free in Autofill.
CVE-2022-0107: Use after free in File Manager API.
CVE-2022-0108: Inappropriate implementation in Navigation.
CVE-2022-0109: Inappropriate implementation in Autofill.
CVE-2022-0110: Incorrect security UI in Autofill.
CVE-2022-0111: Inappropriate implementation in Navigation.
CVE-2022-0112: Incorrect security UI in Browser UI.
CVE-2022-0113: Inappropriate implementation in Blink.
CVE-2022-0114: Out of bounds memory access in Web Serial.
CVE-2022-0115: Uninitialized Use in File API.
CVE-2022-0116: Inappropriate implementation in Compositing.
CVE-2022-0117: Policy bypass in Service Workers.
CVE-2022-0118: Inappropriate implementation in WebShare.
CVE-2022-0120: Inappropriate implementation in Passwords.
CVE-2022-0289: Use after free in Safe browsing.
CVE-2022-0290: Use after free in Site isolation.
CVE-2022-0291: Inappropriate implementation in Storage.
CVE-2022-0292: Inappropriate implementation in Fenced Frames.
CVE-2022-0293: Use after free in Web packaging.
CVE-2022-0294: Inappropriate implementation in Push messaging.
CVE-2022-0295: Use after free in Omnibox.
CVE-2022-0296: Use after free in Printing.
CVE-2022-0297: Use after free in Vulkan.
CVE-2022-0298: Use after free in Scheduling.
CVE-2022-0300: Use after free in Text Input Method Editor.
CVE-2022-0301: Heap buffer overflow in DevTools.
CVE-2022-0302: Use after free in Omnibox.
CVE-2022-0304: Use after free in Bookmarks.
CVE-2022-0305: Inappropriate implementation in Service Worker API.
CVE-2022-0306: Heap buffer overflow in PDFium.
CVE-2022-0307: Use after free in Optimization Guide.
CVE-2022-0308: Use after free in Data Transfer.
CVE-2022-0309: Inappropriate implementation in Autofill.
CVE-2022-0310: Heap buffer overflow in Task Manager.
CVE-2022-0311: Heap buffer overflow in Task Manager.
CVE-2022-0337: Inappropriate implementation in File System API.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~97.0.4692.99~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~97.0.4692.99~1.mga8", rls:"MAGEIA8"))) {
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
