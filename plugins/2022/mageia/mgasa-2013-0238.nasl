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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0238");
  script_cve_id("CVE-2013-4995", "CVE-2013-4996", "CVE-2013-4997", "CVE-2013-4998", "CVE-2013-5000", "CVE-2013-5002", "CVE-2013-5003");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-31 02:59:00 +0000 (Sat, 31 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2013-0238)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0238");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0238.html");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-8.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-9.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-11.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-12.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-14.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-15.php");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10872");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin, phpmyadmin' package(s) announced via the MGASA-2013-0238 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Using a crafted SQL query, it was possible to produce an XSS on the SQL query
form (PMASA-2013-8)(CVE-2013-4995).

In the setup/index.php, using a crafted # hash with a Javascript event,
untrusted JS code could be executed. In the Display chart view, a chart title
containing HTML code was rendered unescaped, leading to possible JavaScript
code execution via events. A malicious user with permission to create
databases or users having HTML tags in their name, could trigger an XSS
vulnerability by issuing a sleep query with a long delay. In the server
status monitor, the query parameters were shown unescaped. By configuring a
malicious URL for the phpMyAdmin logo link in the navigation sidebar,
untrusted script code could be executed when a user clicked the logo.
The setup field for 'List of trusted proxies for IP allow/deny' Ajax
validation code returned the unescaped input on errors, leading to possible
JavaScript execution by entering arbitrary HTML (PMASA-2013-9).
Also, due to not properly validating the version.json file, which is fetched
from the phpMyAdmin.net website, could lead to an XSS attack, if a crafted
version.json file would be presented (PMASA-2013-11).
(CVE-2013-4996, CVE-2013-4997)

By calling some scripts that are part of phpMyAdmin in an unexpected way, it
is possible to trigger phpMyAdmin to display a PHP error message which
contains the full path of the directory where phpMyAdmin is installed
(PMASA-2013-12)(CVE-2013-4998, CVE-2013-5000)

When calling schema_export.php with crafted parameters, it is possible to
trigger an XSS (PMASA-2013-14)(CVE-2013-5002).

Due to a missing validation of parameters passed to schema_export.php and
pmd_pdf.php, it was possible to inject SQL statements that would run with the
privileges of the control user. This gives read and write access to the
tables of the configuration storage database, and if the control user has the
necessary privileges, read access to some tables of the mysql database
(PMASA-2013-15)(CVE-2013-5003).");

  script_tag(name:"affected", value:"'phpmyadmin, phpmyadmin' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~3.5.8.2~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~3.5.8.2~1.mga3", rls:"MAGEIA3"))) {
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
