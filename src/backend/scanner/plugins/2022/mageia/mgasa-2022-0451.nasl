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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0451");
  script_cve_id("CVE-2022-4135", "CVE-2022-4174", "CVE-2022-4175", "CVE-2022-4176", "CVE-2022-4177", "CVE-2022-4178", "CVE-2022-4179", "CVE-2022-4180", "CVE-2022-4181", "CVE-2022-4182", "CVE-2022-4183", "CVE-2022-4184", "CVE-2022-4185", "CVE-2022-4186", "CVE-2022-4187", "CVE-2022-4188", "CVE-2022-4189", "CVE-2022-4190", "CVE-2022-4191", "CVE-2022-4192", "CVE-2022-4193", "CVE-2022-4194", "CVE-2022-4195", "CVE-2022-4262");
  script_tag(name:"creation_date", value:"2022-12-07 04:12:01 +0000 (Wed, 07 Dec 2022)");
  script_version("2022-12-07T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 14:44:00 +0000 (Mon, 28 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0451)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0451");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0451.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31205");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/11/stable-channel-update-for-desktop_29.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0451 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the new 108 branch
with the 108.0.5359.94 release, fixing many bugs and 29 vulnerabilities,
together with 107.0.5304.121 and 108.0.5359.71.

Some of the security fixes are -

CVE-2022-4174: Type Confusion in V8. Reported by Zhenghang Xiao (@Kipreyyy)
on 2022-10-27
CVE-2022-4175: Use after free in Camera Capture. Reported by Leecraso and
Guang Gong of 360 Vulnerability Research Institute on 2022-11-04
CVE-2022-4176: Out of bounds write in Lacros Graphics. Reported by
@ginggilBesel on 2022-09-08
CVE-2022-4177: Use after free in Extensions. Reported by Chaoyuan Peng
(@ret2happy) on 2022-10-28
CVE-2022-4178: Use after free in Mojo. Reported by Sergei Glazunov of
Google Project Zero on 2022-10-18
CVE-2022-4179: Use after free in Audio. Reported by Sergei Glazunov of
Google Project Zero on 2022-10-24
CVE-2022-4180: Use after free in Mojo. Reported by Anonymous on 2022-10-26
CVE-2022-4181: Use after free in Forms. Reported by Aviv A. on 2022-11-09
CVE-2022-4182: Inappropriate implementation in Fenced Frames. Reported by
Peter Nemeth on 2022-09-28
CVE-2022-4183: Insufficient policy enforcement in Popup Blocker. Reported
by David Sievers on 2021-09-22
CVE-2022-4184: Insufficient policy enforcement in Autofill. Reported by
Ahmed ElMasry on 2022-09-01
CVE-2022-4185: Inappropriate implementation in Navigation. Reported by
James Lee (@Windowsrcer) on 2022-10-10
CVE-2022-4186: Insufficient validation of untrusted input in Downloads.
Reported by Luan Herrera (@lbherrera_) on 2022-10-21
CVE-2022-4187: Insufficient policy enforcement in DevTools. Reported by
Axel Chong on 2022-11-04
CVE-2022-4188: Insufficient validation of untrusted input in CORS.
Reported by Philipp Beer (TU Wien) on 2022-06-30
CVE-2022-4189: Insufficient policy enforcement in DevTools. Reported by
NDevTK on 2022-07-15
CVE-2022-4190: Insufficient data validation in Directory. Reported by
Axel Chong on 2022-10-27
CVE-2022-4191: Use after free in Sign-In. Reported by Jaehun Jeong(@n3sk)
of Theori on 2022-10-12
CVE-2022-4192: Use after free in Live Caption. Reported by Samet Bekmezci
@sametbekmezci on 2022-07-14
CVE-2022-4193: Insufficient policy enforcement in File System API.
Reported by Axel Chong on 2022-08-19
CVE-2022-4194: Use after free in Accessibility. Reported by Anonymous on
2022-10-03
CVE-2022-4195: Insufficient policy enforcement in Safe Browsing. Reported
by Eric Lawrence of Microsoft on 2022-10-06
CVE-2022-4135: Heap buffer overflow in GPU. Reported by Clement Lecigne of
Google's Threat Analysis Group on 2022-11-22
CVE-2022-4262: Type Confusion in V8. Reported by Clement Lecigne of
Google's Threat Analysis Group on 2022-11-29

Google is aware that exploits for CVE-2022-4135 and CVE-2022-4262 exist
in the wild.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~108.0.5359.94~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~108.0.5359.94~1.mga8", rls:"MAGEIA8"))) {
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
