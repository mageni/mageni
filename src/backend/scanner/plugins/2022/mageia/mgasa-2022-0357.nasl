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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0357");
  script_cve_id("CVE-2022-3201", "CVE-2022-3304", "CVE-2022-3305", "CVE-2022-3306", "CVE-2022-3307", "CVE-2022-3308", "CVE-2022-3309", "CVE-2022-3310", "CVE-2022-3311", "CVE-2022-3312", "CVE-2022-3313", "CVE-2022-3314", "CVE-2022-3315", "CVE-2022-3316", "CVE-2022-3317", "CVE-2022-3318");
  script_tag(name:"creation_date", value:"2022-10-06 04:26:01 +0000 (Thu, 06 Oct 2022)");
  script_version("2022-10-06T10:41:20+0000");
  script_tag(name:"last_modification", value:"2022-10-06 10:41:20 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 14:37:00 +0000 (Wed, 28 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0357)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0357");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0357.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30905");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30802");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/09/stable-channel-update-for-desktop_27.html");
  script_xref(name:"URL", value:"https://blog.chromium.org/2022/09/chrome-106-beta-new-css-features.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0357 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the new 106 branch
with the 106.0.5249.61 version, fixing many bugs and 20 vulnerabilities,
it brings as well some improvements.

Some of the security fixes are:

High CVE-2022-3304: Use after free in CSS.
High CVE-2022-3201: Insufficient validation of untrusted input in
Developer Tools. Reported by NDevTK on 2022-07-09
High CVE-2022-3305: Use after free in Survey. Reported by Nan
Wang(@eternalsakura13) and Guang Gong of 360 Vulnerability Research
Institute on 2022-04-24
High CVE-2022-3306: Use after free in Survey. Reported by Nan
Wang(@eternalsakura13) and Guang Gong of 360 Vulnerability
Research Institute on 2022-04-27
High CVE-2022-3307: Use after free in Media. Reported by Anonymous
Telecommunications Corp. Ltd. on 2022-05-08
Medium CVE-2022-3308: Insufficient policy enforcement in Developer Tools.
Reported by Andrea Cappa (zi0Black) @ Shielder on 2022-07-08
Medium CVE-2022-3309: Use after free in Assistant. Reported by zh1x1an1221
of Ant Group Tianqiong Security Lab on 2022-07-29
Medium CVE-2022-3310: Insufficient policy enforcement in Custom Tabs.
Reported by Ashwin Agrawal from Optus, Sydney on 2021-08-16
Medium CVE-2022-3311: Use after free in Import. Reported by Samet Bekmezci
@sametbekmezci on 2022-03-04
Medium CVE-2022-3312: Insufficient validation of untrusted input in VPN.
Reported by Andr.Ess on 2022-03-06
Medium CVE-2022-3313: Incorrect security UI in Full Screen. Reported by
Irvan Kurniawan (sourc7) on 2022-04-20
Medium CVE-2022-3314: Use after free in Logging. Reported by Anonymous on
2022-05-24
Medium CVE-2022-3315: Type confusion in Blink. Reported by Anonymous on
2022-05-05
Low CVE-2022-3316: Insufficient validation of untrusted input in Safe
Browsing. Reported by Sven Dysthe (@svn_dy) on 2022-06-07
Low CVE-2022-3317: Insufficient validation of untrusted input in Intents.
Reported by Hafiizh on 2022-02-24
Low CVE-2022-3318: Use after free in ChromeOS Notifications. Reported by
GraVity0 on 2022-04-22");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~106.0.5249.91~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~106.0.5249.91~1.mga8", rls:"MAGEIA8"))) {
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
