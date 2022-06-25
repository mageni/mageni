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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0053");
  script_cve_id("CVE-2021-45085", "CVE-2021-45086", "CVE-2021-45087", "CVE-2021-45088");
  script_tag(name:"creation_date", value:"2022-02-11 03:16:20 +0000 (Fri, 11 Feb 2022)");
  script_version("2022-02-11T10:59:25+0000");
  script_tag(name:"last_modification", value:"2022-02-14 11:09:18 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-17 20:27:00 +0000 (Fri, 17 Dec 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0053)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0053");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0053.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29886");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5042");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'epiphany' package(s) announced via the MGASA-2022-0053 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XSS can occur in GNOME Web (aka Epiphany) before 40.4 and 41.x before 41.1
via an about: page, as demonstrated by ephy-about:overview when a user
visits an XSS payload page often enough to place that page on the Most
Visited list (CVE-2021-45085).

XSS can occur in GNOME Web (aka Epiphany) before 40.4 and 41.x before 41.1
because a server's suggested_filename is used as the pdf_name value in
PDF.js (CVE-2021-45086).

XSS can occur in GNOME Web (aka Epiphany) before 40.4 and 41.x before 41.1
when View Source mode or Reader mode is used, as demonstrated by a page
title (CVE-2021-45087).

XSS can occur in GNOME Web (aka Epiphany) before 40.4 and 41.x before 41.1
via an error page (CVE-2021-45088).");

  script_tag(name:"affected", value:"'epiphany' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~3.38.2~1.1.mga8", rls:"MAGEIA8"))) {
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
