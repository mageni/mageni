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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0419");
  script_cve_id("CVE-2022-3652", "CVE-2022-3653", "CVE-2022-3654", "CVE-2022-3655", "CVE-2022-3656", "CVE-2022-3657", "CVE-2022-3658", "CVE-2022-3659", "CVE-2022-3660", "CVE-2022-3661", "CVE-2022-3723");
  script_tag(name:"creation_date", value:"2022-11-14 04:25:42 +0000 (Mon, 14 Nov 2022)");
  script_version("2022-11-14T04:25:42+0000");
  script_tag(name:"last_modification", value:"2022-11-14 04:25:42 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-02 19:14:00 +0000 (Wed, 02 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0419)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0419");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0419.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31033");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_25.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_27.html");
  script_xref(name:"URL", value:"https://developer.chrome.com/blog/chrome-107-beta/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0419 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the new 107 branch
with the 107.0.5304.87 version, fixing many bugs and 15 vulnerabilities,
together with 107.0.5304.68.

Some of the security fixes are:

High CVE-2022-3652: Type Confusion in V8. Reported by srodulv and ZNMchtss
at S.S.L Team on 2022-09-30
High CVE-2022-3653: Heap buffer overflow in Vulkan. Reported by SeongHwan
Park (SeHwa) on 2022-08-19
High CVE-2022-3654: Use after free in Layout. Reported by Sergei Glazunov
of Google Project Zero on 2022-09-19
Medium CVE-2022-3655: Heap buffer overflow in Media Galleries. Reported by
koocola(@alo_cook) and Guang Gong of 360 Vulnerability Research Institute
on 2022-07-11
Medium CVE-2022-3656: Insufficient data validation in File System.
Reported by Ron Masas, Imperva on 2022-07-18
Medium CVE-2022-3657: Use after free in Extensions. Reported by Omri
Bushari, Talon Cyber Security on 2022-08-09
Medium CVE-2022-3658: Use after free in Feedback service on Chrome OS.
Reported by Nan Wang(@eternalsakura13) and Guang Gong of 360 Vulnerability
Research Institute on 2022-08-14
Medium CVE-2022-3659: Use after free in Accessibility. Reported by
@ginggilBesel on 2022-08-23
Medium CVE-2022-3660: Inappropriate implementation in Full screen mode.
Reported by Irvan Kurniawan (sourc7) on 2022-05-20
Low CVE-2022-3661: Insufficient data validation in Extensions. Reported by
Young Min Kim (@ylemkimon), CompSec Lab at Seoul National University on
2022-08-04

High CVE-2022-3723: Type Confusion in V8. Reported by Jan Vojtesek,
Milanek, and Przemek Gmerek of Avast on 2022-10-25");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~107.0.5304.110~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~107.0.5304.110~1.mga8", rls:"MAGEIA8"))) {
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
