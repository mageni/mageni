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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0471");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2017-0471)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0471");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0471.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22263");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-9/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.7.2/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.7.3/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.7.4/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.7.5/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.7.6/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.7.7/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2017/12/23/phpmyadmin-477-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the MGASA-2017-0471 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to an XSRF/CSRF vulnerability in phpMyAdmin before 4.7.7, by
deceiving a user to click on a crafted URL, it is possible to perform
harmful database operations such as deleting records,
dropping/truncating tables etc (PMASA-2017-9).

The phpmyadmin package has been updated to version 4.7.7 to fix this
issue and other bugs.

Note that phpMyAdmin 4.4.x in Mageia 5 is no longer supported. Users of
the phpmyadmin package should upgrade to Mageia 6.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~4.7.7~1.mga6", rls:"MAGEIA6"))) {
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
