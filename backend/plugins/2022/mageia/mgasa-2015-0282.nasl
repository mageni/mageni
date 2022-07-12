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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0282");
  script_cve_id("CVE-2015-5069", "CVE-2015-5070");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-10 14:54:00 +0000 (Tue, 10 Oct 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0282)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0282");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0282.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16208");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/06/25/12");
  script_xref(name:"URL", value:"http://forums.wesnoth.org/viewtopic.php?t=42776");
  script_xref(name:"URL", value:"https://github.com/wesnoth/wesnoth/commit/055fea16479a755d6744a52f78f63548b692c440");
  script_xref(name:"URL", value:"https://github.com/wesnoth/wesnoth/commit/d20f8015bc3653a10d6d4dfd751e62651d1180b7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wesnoth' package(s) announced via the MGASA-2015-0282 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tomb Lohmus discovered that the Lua API and preprocessor in the Battle for
Wesnoth game up to version 1.12.2 included could lead to client-side
authentication information disclosure using maliciously crafted files
with the .pdb extension (CVE-2015-5069, CVE-2015-5070).

This issue has been fixed using patches from upstream's 1.10.x branch.");

  script_tag(name:"affected", value:"'wesnoth' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"wesnoth", rpm:"wesnoth~1.10.7~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wesnoth-data", rpm:"wesnoth-data~1.10.7~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wesnoth-server", rpm:"wesnoth-server~1.10.7~2.2.mga4", rls:"MAGEIA4"))) {
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
