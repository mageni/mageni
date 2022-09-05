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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0318");
  script_cve_id("CVE-2022-3038", "CVE-2022-3039", "CVE-2022-3040", "CVE-2022-3041", "CVE-2022-3042", "CVE-2022-3043", "CVE-2022-3044", "CVE-2022-3045", "CVE-2022-3046", "CVE-2022-3047", "CVE-2022-3048", "CVE-2022-3049", "CVE-2022-3050", "CVE-2022-3051", "CVE-2022-3052", "CVE-2022-3053", "CVE-2022-3054", "CVE-2022-3055", "CVE-2022-3056", "CVE-2022-3057", "CVE-2022-3058", "CVE-2022-3071", "CVE-2022-3075");
  script_tag(name:"creation_date", value:"2022-09-05 05:04:07 +0000 (Mon, 05 Sep 2022)");
  script_version("2022-09-05T05:04:07+0000");
  script_tag(name:"last_modification", value:"2022-09-05 05:04:07 +0000 (Mon, 05 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0318)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0318");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0318.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30802");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/08/stable-channel-update-for-desktop_30.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/09/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://blog.chromium.org/2022/08/chrome-105-beta-custom-highlighting.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0318 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the new 105 branch
with the 105.0.5195.102 version, fixing many bugs and 25 vulnerabilities.

Google is aware of reports that an exploit for CVE-2022-3075 exists in the
wild. Some of the addressed CVE are listed below:

High CVE-2022-3075: Insufficient data validation in Mojo. Reported by
Anonymous on 2022-08-30

Critical CVE-2022-3038: Use after free in Network Service. Reported by
Sergei Glazunov of Google Project Zero on 2022-06-28

High CVE-2022-3039: Use after free in WebSQL. Reported by Nan
Wang(@eternalsakura13) and Guang Gong of 360 Vulnerability Research
Institute on 2022-07-11

High CVE-2022-3040: Use after free in Layout. Reported by Anonymous on
2022-07-03

High CVE-2022-3041: Use after free in WebSQL. Reported by Ziling Chen and
Nan Wang(@eternalsakura13) of 360 Vulnerability Research Institute on
2022-07-20

High CVE-2022-3042: Use after free in PhoneHub. Reported by
koocola(@alo_cook) and Guang Gong of 360 Vulnerability Research Institute
on 2022-06-22

High CVE-2022-3043: Heap buffer overflow in Screen Capture. Reported by
@ginggilBesel on 2022-06-16

High CVE-2022-3044: Inappropriate implementation in Site Isolation.
Reported by Lucas Pinheiro, Microsoft Browser Vulnerability Research on
2020-02-12

High CVE-2022-3045: Insufficient validation of untrusted input in V8.
Reported by Ben Noordhuis <info@bnoordhuis.nl> on 2022-06-26

High CVE-2022-3046: Use after free in Browser Tag. Reported by Rong Jian
of VRI on 2022-07-21

High CVE-2022-3071: Use after free in Tab Strip. Reported by @ginggilBesel
on 2022-06-06

Medium CVE-2022-3047: Insufficient policy enforcement in Extensions API.
Reported by Maurice Dauer on 2022-07-07

Medium CVE-2022-3048: Inappropriate implementation in Chrome OS
lockscreen. Reported by Andr.Ess on 2022-03-06

Medium CVE-2022-3049: Use after free in SplitScreen. Reported by
@ginggilBesel on 2022-04-17

Medium CVE-2022-3050: Heap buffer overflow in WebUI. Reported by Zhihua
Yao of KunLun Lab on 2022-06-17

Medium CVE-2022-3051: Heap buffer overflow in Exosphere. Reported by
@ginggilBesel on 2022-07-18

Medium CVE-2022-3052: Heap buffer overflow in Window Manager. Reported
by Khalil Zhani on 2022-07-21

Medium CVE-2022-3053: Inappropriate implementation in Pointer Lock.
Reported by Jesper van den Ende (Pelican Party Studios) on 2021-11-08

Medium CVE-2022-3054: Insufficient policy enforcement in DevTools.
Reported by Kuilin Li on 2022-01-24

Medium CVE-2022-3055: Use after free in Passwords. Reported by Weipeng
Jiang (@Krace) and Guang Gong of 360 Vulnerability Research Institute on
2022-08-11

Low CVE-2022-3056: Insufficient policy enforcement in Content Security
Policy. Reported by Anonymous on 2022-05-26

Low CVE-2022-3057: Inappropriate implementation in iframe Sandbox.
Reported by Gareth Heyes on 2022-06-16

Low CVE-2022-3058: Use after free in Sign-In Flow. Reported by raven at
KunLun lab on 2022-06-20");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~105.0.5195.102~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~105.0.5195.102~1.mga8", rls:"MAGEIA8"))) {
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
