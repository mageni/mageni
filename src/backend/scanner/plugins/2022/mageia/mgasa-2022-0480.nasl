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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0480");
  script_cve_id("CVE-2022-4436", "CVE-2022-4437", "CVE-2022-4438", "CVE-2022-4439", "CVE-2022-4440");
  script_tag(name:"creation_date", value:"2022-12-26 04:12:47 +0000 (Mon, 26 Dec 2022)");
  script_version("2022-12-27T10:18:20+0000");
  script_tag(name:"last_modification", value:"2022-12-27 10:18:20 +0000 (Tue, 27 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-16 16:48:00 +0000 (Fri, 16 Dec 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0480");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0480.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31288");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/12/stable-channel-update-for-desktop_13.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the 108.0.5359.124
release, fixing 8 vulnerabilities.

Some of the security fixes are ...

High CVE-2022-4436: Use after free in Blink Media. Reported by Anonymous
on 2022-11-15

High CVE-2022-4437: Use after free in Mojo IPC. Reported by
koocola(@alo_cook) and Guang Gong of 360 Vulnerability Research
Institute on 2022-11-30

High CVE-2022-4438: Use after free in Blink Frames. Reported by Anonymous
on 2022-11-07

High CVE-2022-4439: Use after free in Aura. Reported by Anonymous on
2022-11-22

Medium CVE-2022-4440: Use after free in Profiles. Reported by Anonymous on
2022-11-09");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~108.0.5359.124~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~108.0.5359.124~1.mga8", rls:"MAGEIA8"))) {
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
