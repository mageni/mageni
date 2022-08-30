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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0307");
  script_cve_id("CVE-2022-2852", "CVE-2022-2853", "CVE-2022-2854", "CVE-2022-2855", "CVE-2022-2856", "CVE-2022-2857", "CVE-2022-2858", "CVE-2022-2859", "CVE-2022-2860", "CVE-2022-2861");
  script_tag(name:"creation_date", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T04:58:48+0000");
  script_tag(name:"last_modification", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0307");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0307.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30756");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/08/stable-channel-update-for-desktop_16.html");
  script_xref(name:"URL", value:"https://blog.chromium.org/2022/06/chrome-104-beta-new-media-query-syntax.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the 104.0.5112.101
branch, fixing many bugs and 11 CVE.
Google is aware that an exploit for CVE-2022-2856 exists in the wild.
Some of the addressed CVE are listed below:
Critical CVE-2022-2852: Use after free in FedCM.
High CVE-2022-2854: Use after free in SwiftShader.
High CVE-2022-2855: Use after free in ANGLE.
High CVE-2022-2857: Use after free in Blink.
High CVE-2022-2858: Use after free in Sign-In Flow.
High CVE-2022-2853: Heap buffer overflow in Downloads.
High CVE-2022-2856: Insufficient validation of untrusted input in Intents.
Medium CVE-2022-2859: Use after free in Chrome OS Shell.
Medium CVE-2022-2860: Insufficient policy enforcement in Cookies.
Medium CVE-2022-2861: Inappropriate implementation in Extensions API.
Various fixes from internal audits, fuzzing and other initiatives");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~104.0.5112.101~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~104.0.5112.101~1.mga8", rls:"MAGEIA8"))) {
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
