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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0211");
  script_cve_id("CVE-2022-1853", "CVE-2022-1854", "CVE-2022-1855", "CVE-2022-1856", "CVE-2022-1857", "CVE-2022-1858", "CVE-2022-1859", "CVE-2022-1860", "CVE-2022-1861", "CVE-2022-1862", "CVE-2022-1863", "CVE-2022-1864", "CVE-2022-1865", "CVE-2022-1866", "CVE-2022-1867", "CVE-2022-1868", "CVE-2022-1869", "CVE-2022-1870", "CVE-2022-1871", "CVE-2022-1872", "CVE-2022-1873", "CVE-2022-1874", "CVE-2022-1875", "CVE-2022-1876");
  script_tag(name:"creation_date", value:"2022-05-30 04:37:27 +0000 (Mon, 30 May 2022)");
  script_version("2022-05-30T04:37:27+0000");
  script_tag(name:"last_modification", value:"2022-05-30 04:37:27 +0000 (Mon, 30 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0211)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0211");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0211.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30470");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/05/stable-channel-update-for-desktop_24.html");
  script_xref(name:"URL", value:"https://blog.chromium.org/2022/04/chrome-102-window-controls-overlay-host.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0211 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the 102.0.5005.61
version, fixing many bugs and 32 CVE. Some of them are listed below:
CVE-2022-1853: Use after free in Indexed DB.
CVE-2022-1854: Use after free in ANGLE.
CVE-2022-1855: Use after free in Messaging.
CVE-2022-1856: Use after free in User Education.
CVE-2022-1857: Insufficient policy enforcement in File System API.
CVE-2022-1858: Out of bounds read in DevTools.
CVE-2022-1859: Use after free in Performance Manager.
CVE-2022-1860: Use after free in UI Foundations.
CVE-2022-1861: Use after free in Sharing.
CVE-2022-1862: Inappropriate implementation in Extensions.
CVE-2022-1863: Use after free in Tab Groups.
CVE-2022-1864: Use after free in WebApp Installs.
CVE-2022-1865: Use after free in Bookmarks.
CVE-2022-1866: Use after free in Tablet Mode.
CVE-2022-1867: Insufficient validation of untrusted input in Data Transfer.
CVE-2022-1868: Inappropriate implementation in Extensions API.
CVE-2022-1869: Type Confusion in V8.
CVE-2022-1870: Use after free in App Service.
CVE-2022-1871: Insufficient policy enforcement in File System API.
CVE-2022-1872: Insufficient policy enforcement in Extensions API.
CVE-2022-1873: Insufficient policy enforcement in COOP.
CVE-2022-1874: Insufficient policy enforcement in Safe Browsing.
CVE-2022-1875: Inappropriate implementation in PDF.
CVE-2022-1876: Heap buffer overflow in DevTools.
Various fixes from internal audits, fuzzing and other initiatives.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~102.0.5005.61~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~102.0.5005.61~1.mga8", rls:"MAGEIA8"))) {
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
