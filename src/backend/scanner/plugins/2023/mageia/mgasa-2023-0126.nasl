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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0126");
  script_cve_id("CVE-2023-27586");
  script_tag(name:"creation_date", value:"2023-04-07 04:12:44 +0000 (Fri, 07 Apr 2023)");
  script_version("2023-04-07T10:09:45+0000");
  script_tag(name:"last_modification", value:"2023-04-07 10:09:45 +0000 (Fri, 07 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 18:23:00 +0000 (Thu, 23 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0126)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0126");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0126.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31730");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/5HDBMOMLE6GFKXPLKIWFWM2Q6V4DQKXP/");
  script_xref(name:"URL", value:"https://github.com/Kozea/CairoSVG/security/advisories/GHSA-rwmf-w63j-p7gv");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-cairosvg' package(s) announced via the MGASA-2023-0126 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CairoSVG is an SVG converter based on Cairo, a 2D graphics library. Prior
to version 2.7.0, Cairo can send requests to external hosts when
processing SVG files. A malicious actor could send a specially crafted SVG
file that allows them to perform a server-side request forgery or denial
of service. Version 2.7.0 disables CairoSVG's ability to access other
files online by default. (CVE-2023-27586)");

  script_tag(name:"affected", value:"'python-cairosvg' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"cairosvg", rpm:"cairosvg~2.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cairosvg", rpm:"python-cairosvg~2.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cairosvg", rpm:"python3-cairosvg~2.5.1~1.2.mga8", rls:"MAGEIA8"))) {
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
