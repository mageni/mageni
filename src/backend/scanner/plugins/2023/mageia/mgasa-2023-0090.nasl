# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0090");
  script_cve_id("CVE-2023-1213", "CVE-2023-1214", "CVE-2023-1215", "CVE-2023-1216", "CVE-2023-1217", "CVE-2023-1218", "CVE-2023-1219", "CVE-2023-1220", "CVE-2023-1221", "CVE-2023-1222", "CVE-2023-1223", "CVE-2023-1224", "CVE-2023-1225", "CVE-2023-1226", "CVE-2023-1227", "CVE-2023-1228", "CVE-2023-1229", "CVE-2023-1230", "CVE-2023-1231", "CVE-2023-1232", "CVE-2023-1233", "CVE-2023-1234", "CVE-2023-1235", "CVE-2023-1236");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-11 02:37:00 +0000 (Sat, 11 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0090)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0090");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0090.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31645");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/03/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://www.howtogeek.com/877321/whats-new-in-chrome-111/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2023-0090 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"High CVE-2023-1213: Use after free in Swiftshader. Reported by Jaehun
Jeong(@n3sk) of Theori on 2023-01-30

High CVE-2023-1214: Type Confusion in V8. Reported by Man Yue Mo of GitHub
Security Lab on 2023-02-03

High CVE-2023-1215: Type Confusion in CSS. Reported by Anonymous on
2023-02-17

High CVE-2023-1216: Use after free in DevTools. Reported by Ganjiang
Zhou(@refrain_areu) of ChaMd5-H1 team on 2023-02-21

High CVE-2023-1217: Stack buffer overflow in Crash reporting. Reported by
sunburst of Ant Group Tianqiong Security Lab on 2023-02-03

High CVE-2023-1218: Use after free in WebRTC. Reported by Anonymous on
2023-02-07

High CVE-2023-1219: Heap buffer overflow in Metrics. Reported by Sergei
Glazunov of Google Project Zero on 2023-02-13

High CVE-2023-1220: Heap buffer overflow in UMA. Reported by Sergei
Glazunov of Google Project Zero on 2023-02-17

Medium CVE-2023-1221: Insufficient policy enforcement in Extensions API.
Reported by Ahmed ElMasry on 2022-11-16

Medium CVE-2023-1222: Heap buffer overflow in Web Audio API. Reported by
Cassidy Kim(@cassidy6564) on 2022-12-24

Medium CVE-2023-1223: Insufficient policy enforcement in Autofill.
Reported by Ahmed ElMasry on 2022-12-07

Medium CVE-2023-1224: Insufficient policy enforcement in Web Payments API.
Reported by Thomas Orlita on 2022-12-25

Medium CVE-2023-1225: Insufficient policy enforcement in Navigation.
Reported by Roberto Ffrench-Davis @Lihaft on 2023-01-20

Medium CVE-2023-1226: Insufficient policy enforcement in Web Payments API.
Reported by Anonymous on 2019-10-10

Medium CVE-2023-1227: Use after free in Core. Reported by @ginggilBesel on
2022-07-31

Medium CVE-2023-1228: Insufficient policy enforcement in Intents. Reported
by Axel Chong on 2022-09-18

Medium CVE-2023-1229: Inappropriate implementation in Permission prompts.
Reported by Thomas Orlita on 2020-12-20

Medium CVE-2023-1230: Inappropriate implementation in WebApp Installs.
Reported by Axel Chong on 2022-12-30

Medium CVE-2023-1231: Inappropriate implementation in Autofill. Reported
by Yan Zhu, Brave on 2021-11-30

Low CVE-2023-1232: Insufficient policy enforcement in Resource Timing.
Reported by Sohom Datta on 2022-07-24

Low CVE-2023-1233: Insufficient policy enforcement in Resource Timing.
Reported by Soroush Karami on 2020-01-25

Low CVE-2023-1234: Inappropriate implementation in Intents. Reported by
Axel Chong on 2023-01-03

Low CVE-2023-1235: Type Confusion in DevTools. Reported by raven at
KunLun lab on 2023-01-03

Low CVE-2023-1236: Inappropriate implementation in Internals. Reported by
Alesandro Ortiz on 2022-10-14");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~111.0.5563.64~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~111.0.5563.64~1.mga8", rls:"MAGEIA8"))) {
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
