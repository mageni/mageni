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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0188");
  script_cve_id("CVE-2022-1633", "CVE-2022-1634", "CVE-2022-1635", "CVE-2022-1636", "CVE-2022-1637", "CVE-2022-1638", "CVE-2022-1639", "CVE-2022-1640", "CVE-2022-1641");
  script_tag(name:"creation_date", value:"2022-05-19 07:28:20 +0000 (Thu, 19 May 2022)");
  script_version("2022-05-19T07:28:20+0000");
  script_tag(name:"last_modification", value:"2022-05-19 09:49:33 +0000 (Thu, 19 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0188)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0188");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0188.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30411");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/05/stable-channel-update-for-desktop_10.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0188 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the 101.0.4951.64
version, fixing many bugs and 13 CVE. Some of them are listed below:

[1316990] High CVE-2022-1633: Use after free in Sharesheet. Reported by
Khalil Zhani on 2022-04-18
[1314908] High CVE-2022-1634: Use after free in Browser UI. Reported by
Khalil Zhani on 2022-04-09
[1319797] High CVE-2022-1635: Use after free in Permission Prompts.
Reported by Anonymous on 2022-04-26
[1297283] High CVE-2022-1636: Use after free in Performance APIs.
Reported by Seth Brenith, Microsoft on 2022-02-15
[1311820] High CVE-2022-1637: Inappropriate implementation in Web
Contents. Reported by Alesandro Ortiz on 2022-03-31
[1316946] High CVE-2022-1638: Heap buffer overflow in V8
Internationalization. Reported by DoHyun Lee (@l33d0hyun) of DNSLab, Korea
University on 2022-04-17
[1317650] High CVE-2022-1639: Use after free in ANGLE. Reported by
SeongHwan Park (SeHwa) on 2022-04-19
[1320592] High CVE-2022-1640: Use after free in Sharing. Reported by
Weipeng Jiang (@Krace) and Guang Gong of 360 Vulnerability Research
Institute on 2022-04-28
[1305068] Medium CVE-2022-1641: Use after free in Web UI Diagnostics.
Reported by Rong Jian of VRI on 2022-03-10

[1323855] Various fixes from internal audits, fuzzing and other
initiatives");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~101.0.4951.64~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~101.0.4951.64~1.mga8", rls:"MAGEIA8"))) {
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
