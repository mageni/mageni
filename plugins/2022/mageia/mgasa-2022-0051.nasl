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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0051");
  script_cve_id("CVE-2022-24130");
  script_tag(name:"creation_date", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");
  script_version("2022-02-09T07:40:33+0000");
  script_tag(name:"last_modification", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-04 20:06:00 +0000 (Fri, 04 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0051)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0051");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0051.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29975");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/31/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xterm' package(s) announced via the MGASA-2022-0051 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xterm through Patch 370, when Sixel support is enabled, allows attackers
to trigger a buffer overflow in set_sixel in graphics_sixel.c via crafted
text. (CVE-2022-24130)");

  script_tag(name:"affected", value:"'xterm' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"xterm", rpm:"xterm~363~1.2.mga8", rls:"MAGEIA8"))) {
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
