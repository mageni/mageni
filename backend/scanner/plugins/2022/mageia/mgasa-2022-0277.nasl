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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0277");
  script_cve_id("CVE-2022-2603", "CVE-2022-2604", "CVE-2022-2605", "CVE-2022-2606", "CVE-2022-2607", "CVE-2022-2608", "CVE-2022-2609", "CVE-2022-2610", "CVE-2022-2611", "CVE-2022-2612", "CVE-2022-2613", "CVE-2022-2614", "CVE-2022-2615", "CVE-2022-2616", "CVE-2022-2617", "CVE-2022-2618", "CVE-2022-2619", "CVE-2022-2620", "CVE-2022-2621", "CVE-2022-2622", "CVE-2022-2623", "CVE-2022-2624");
  script_tag(name:"creation_date", value:"2022-08-08 11:35:39 +0000 (Mon, 08 Aug 2022)");
  script_version("2022-08-08T11:35:39+0000");
  script_tag(name:"last_modification", value:"2022-08-08 11:35:39 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0277)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0277");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0277.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30695");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/08/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://blog.chromium.org/2022/06/chrome-104-beta-new-media-query-syntax.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0277 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1325699] High CVE-2022-2603: Use after free in Omnibox. Reported by
Anonymous on 2022-05-16
[1335316] High CVE-2022-2604: Use after free in Safe Browsing. Reported by
Nan Wang(@eternalsakura13) and Guang Gong of 360 Alpha Lab on 2022-06-10
[1338470] High CVE-2022-2605: Out of bounds read in Dawn. Reported by
Looben Yang on 2022-06-22
[1330489] High CVE-2022-2606: Use after free in Managed devices API.
Reported by Nan Wang(@eternalsakura13) and Guang Gong of 360 Alpha Lab
on 2022-05-31
[1286203] High CVE-2022-2607: Use after free in Tab Strip. Reported by
@ginggilBesel on 2022-01-11
[1330775] High CVE-2022-2608: Use after free in Overview Mode. Reported by
Khalil Zhani on 2022-06-01
[1338560] High CVE-2022-2609: Use after free in Nearby Share. Reported by
koocola(@alo_cook) and Guang Gong of 360 Vulnerability Research Institute
on 2022-06-22
[1278255] Medium CVE-2022-2610: Insufficient policy enforcement in
Background Fetch. Reported by Maurice Dauer on 2021-12-09
[1320538] Medium CVE-2022-2611: Inappropriate implementation in Fullscreen
API. Reported by Irvan Kurniawan (sourc7) on 2022-04-28
[1321350] Medium CVE-2022-2612: Side-channel information leakage in
Keyboard input. Reported by Erik Kraft (erik.kraft5@gmx.at), Martin
Schwarzl (martin.schwarzl@iaik.tugraz.at) on 2022-04-30
[1325256] Medium CVE-2022-2613: Use after free in Input. Reported by Piotr
Tworek (Vewd) on 2022-05-13
[1341907] Medium CVE-2022-2614: Use after free in Sign-In Flow. Reported
by raven at KunLun lab on 2022-07-05
[1268580] Medium CVE-2022-2615: Insufficient policy enforcement in
Cookies. Reported by Maurice Dauer on 2021-11-10
[1302159] Medium CVE-2022-2616: Inappropriate implementation in Extensions
API. Reported by Alesandro Ortiz on 2022-03-02
[1292451] Medium CVE-2022-2617: Use after free in Extensions API. Reported
by @ginggilBesel on 2022-01-31
[1308422] Medium CVE-2022-2618: Insufficient validation of untrusted input
in Internals. Reported by asnine on 2022-03-21
[1332881] Medium CVE-2022-2619: Insufficient validation of untrusted input
in Settings. Reported by Oliver Dunk on 2022-06-04
[1337304] Medium CVE-2022-2620: Use after free in WebUI. Reported by Nan
Wang(@eternalsakura13) and Guang Gong of 360 Alpha Lab on 2022-06-17
[1323449] Medium CVE-2022-2621: Use after free in Extensions. Reported by
Huyna at Viettel Cyber Security on 2022-05-07
[1332392] Medium CVE-2022-2622: Insufficient validation of untrusted input
in Safe Browsing. Reported by Imre Rad (@ImreRad) and @j00sean on
2022-06-03
[1337798] Medium CVE-2022-2623: Use after free in Offline. Reported by
raven at KunLun lab on 2022-06-20
[1339745] Medium CVE-2022-2624: Heap buffer overflow in PDF. Reported by
YU-CHANG CHEN and CHIH-YEN CHANG, working with DEVCORE Internship Program
on 2022-06-27
[1251653] Various fixes from internal audits, fuzzing and other initiatives");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~104.0.5112.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~104.0.5112.79~1.mga8", rls:"MAGEIA8"))) {
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
