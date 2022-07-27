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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0416");
  script_cve_id("CVE-2016-9847", "CVE-2016-9848", "CVE-2016-9849", "CVE-2016-9850", "CVE-2016-9851", "CVE-2016-9852", "CVE-2016-9853", "CVE-2016-9854", "CVE-2016-9855", "CVE-2016-9856", "CVE-2016-9857", "CVE-2016-9858", "CVE-2016-9859", "CVE-2016-9860", "CVE-2016-9861", "CVE-2016-9864", "CVE-2016-9865", "CVE-2016-9866");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0416)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0416");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0416.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19841");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-58/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-59/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-60/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-61/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-62/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-63/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-64/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-65/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-66/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-69/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-70/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-71/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.4.15.9/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2016/11/25/phpmyadmin-401018-44159-and-465-are-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the MGASA-2016-0416 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In phpMyAdmin before 4.4.15.9, when the user does not specify a
blowfish_secret key for encrypting cookies, phpMyAdmin generates one at
runtime. A vulnerability was reported where the way this value is created
using a weak algorithm. This could allow an attacker to determine the
user's blowfish_secret and potentially decrypt their cookies
(CVE-2016-9847).

In phpMyAdmin before 4.4.15.9, phpinfo.php shows PHP information including
values of sensitive HttpOnly cookies (CVE-2016-9848).

In phpMyAdmin before 4.4.15.9, it is possible to bypass AllowRoot
restriction ($cfg['Servers'][$i]['AllowRoot']) and deny rules for username
by using Null Byte in the username (CVE-2016-9849).

In phpMyAdmin before 4.4.15.9, a vulnerability in username matching for
the allow/deny rules may result in wrong matches and detection of the
username in the rule due to non-constant execution time (CVE-2016-9850).

In phpMyAdmin before 4.4.15.9, with a crafted request parameter value it
is possible to bypass the logout timeout (CVE-2016-9851).

In phpMyAdmin before 4.4.15.9, by calling some scripts that are part of
phpMyAdmin in an unexpected way, it is possible to trigger phpMyAdmin to
display a PHP error message which contains the full path of the directory
where phpMyAdmin is installed. During an execution timeout in the export
functionality, the errors containing the full path of the directory of
phpMyAdmin is written to the export file (CVE-2016-9852, CVE-2016-9853,
CVE-2016-9854, CVE-2016-9855).

In phpMyAdmin before 4.4.15.9, several XSS vulnerabilities have been
reported, including an improper fix for PMASA-2016-10 and a weakness in a
regular expression using in some JavaScript processing (CVE-2016-9856,
CVE-2016-9857).

In phpMyAdmin before 4.4.15.9, with a crafted request parameter value it
is possible to initiate a denial of service attack in saved searches
feature (CVE-2016-9858).

In phpMyAdmin before 4.4.15.9, with a crafted request parameter value it
is possible to initiate a denial of service attack in import feature
(CVE-2016-9859).

In phpMyAdmin before 4.4.15.9, an unauthenticated user can execute a
denial of service attack when phpMyAdmin is running with
$cfg['AllowArbitraryServer']=true, (CVE-2016-9860).

In phpMyAdmin before 4.4.15.9, due to the limitation in URL matching, it
was possible to bypass the URL white-list protection (CVE-2016-9861).

In phpMyAdmin before 4.4.15.9, with a crafted username or a table name,
it was possible to inject SQL statements in the tracking functionality
that would run with the privileges of the control user. This gives read
and write access to the tables of the configuration storage database, and
if the control user has the necessary privileges, read access to some
tables of the mysql database (CVE-2016-9864).

In phpMyAdmin before 4.4.15.9, due to a bug in serialized string parsing,
it was possible to bypass the protection offered by ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~4.4.15.9~1.mga5", rls:"MAGEIA5"))) {
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
