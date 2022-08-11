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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0240");
  script_cve_id("CVE-2016-5701", "CVE-2016-5703", "CVE-2016-5705", "CVE-2016-5706", "CVE-2016-5730", "CVE-2016-5731", "CVE-2016-5733", "CVE-2016-5739");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2016-0240)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0240");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0240.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18777");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-17/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-19/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-21/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-22/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-23/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-24/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-26/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-28/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2016/6/23/phpmyadmin-401016-44157-and-463-are-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the MGASA-2016-0240 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In phpMyAdmin before 4.4.15.7, a vulnerability was discovered that allows
a BBCode injection to setup script in case it's not accessed on https
(CVE-2016-5701).

In phpMyAdmin before 4.4.15.7, a vulnerability was discovered that allows
an SQL injection attack to run arbitrary commands as the control user
(CVE-2016-5703).

In phpMyAdmin before 4.4.15.7, XSS vulnerabilities were discovered in the
user privileges page, the error console, and the central columns, query
bookmarks, and user groups features (CVE-2016-5705).

In phpMyAdmin before 4.4.15.7, a Denial Of Service (DOS) attack was
discovered in the way phpMyAdmin loads some JavaScript files
(CVE-2016-5706).

In phpMyAdmin before 4.4.15.7, by specially crafting requests in the
following areas, it is possible to trigger phpMyAdmin to display a PHP
error message which contains the full path of the directory where
phpMyAdmin is installed (CVE-2016-5730).

In phpMyAdmin before 4.4.15.7, with a specially crafted request, it is
possible to trigger an XSS attack through the example OpenID
authentication script (CVE-2016-5731).

In phpMyAdmin before 4.4.15.7, XSS vulnerabilities were found through
specially crafted databases, in AJAX error handling, and in the
Transformation, Designer, charts, and zoom search features
(CVE-2016-5733).

In phpMyAdmin before 4.4.15.7, a vulnerability was reported where a
specially crafted Transformation could be used to leak information
including the authentication token. This could be used to direct a CSRF
attack against a user (CVE-2016-5739).");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~4.4.15.7~1.mga5", rls:"MAGEIA5"))) {
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
