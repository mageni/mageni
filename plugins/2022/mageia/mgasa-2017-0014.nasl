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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0014");
  script_cve_id("CVE-2016-7867", "CVE-2016-7868", "CVE-2016-7869", "CVE-2016-7870", "CVE-2016-7871", "CVE-2016-7872", "CVE-2016-7873", "CVE-2016-7874", "CVE-2016-7875", "CVE-2016-7876", "CVE-2016-7877", "CVE-2016-7878", "CVE-2016-7879", "CVE-2016-7880", "CVE-2016-7881", "CVE-2016-7890", "CVE-2016-7892", "CVE-2017-2925", "CVE-2017-2926", "CVE-2017-2927", "CVE-2017-2928", "CVE-2017-2930", "CVE-2017-2931", "CVE-2017-2932", "CVE-2017-2933", "CVE-2017-2934", "CVE-2017-2935", "CVE-2017-2936", "CVE-2017-2937", "CVE-2017-2938");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0014");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0014.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19960");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-39.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-02.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2017-0014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 24.0.0.194 contains fixes to critical security
vulnerabilities found in earlier versions that could potentially allow
an attacker to take control of the affected system.

Adobe is aware of a report that an exploit for CVE-2016-7892 exists in
the wild, and is being used in limited, targeted attacks against users
running Internet Explorer (32-bit) on Windows.

This update resolves security bypass vulnerabilities (CVE-2016-7890,
CVE-2017-2938).

This update resolves use-after-free vulnerabilities that could lead to
code execution (CVE-2016-7872, CVE-2016-7877, CVE-2016-7878,
CVE-2016-7879, CVE-2016-7880, CVE-2016-7881, CVE-2016-7892,
CVE-2017-2932, CVE-2017-2936, CVE-2017-2937).

This update resolves buffer overflow vulnerabilities that could lead to
code execution (CVE-2016-7867, CVE-2016-7868, CVE-2016-7869,
CVE-2016-7870, CVE-2017-2927, CVE-2017-2933, CVE-2017-2934,
CVE-2017-2935).

This update resolves memory corruption vulnerabilities that could lead
to code execution (CVE-2016-7871, CVE-2016-7873, CVE-2016-7874,
CVE-2016-7875, CVE-2016-7876, CVE-2017-2925, CVE-2017-2926,
CVE-2017-2928, CVE-2017-2930, CVE-2017-2931).

Note that Adobe has dropped Adobe Access DRM support from all their
Linux releases since their 11.2 release series (which no longer gets
security updates), so any Flash content protected with Adobe Access
will no longer work.");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~24.0.0.194~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~24.0.0.194~1.mga5.nonfree", rls:"MAGEIA5"))) {
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
