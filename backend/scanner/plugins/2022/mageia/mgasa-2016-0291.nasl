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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0291");
  script_cve_id("CVE-2016-6606", "CVE-2016-6607", "CVE-2016-6609", "CVE-2016-6610", "CVE-2016-6611", "CVE-2016-6612", "CVE-2016-6613", "CVE-2016-6614", "CVE-2016-6615", "CVE-2016-6616", "CVE-2016-6618", "CVE-2016-6619", "CVE-2016-6620", "CVE-2016-6622", "CVE-2016-6623", "CVE-2016-6624", "CVE-2016-6625", "CVE-2016-6626", "CVE-2016-6627", "CVE-2016-6628", "CVE-2016-6629", "CVE-2016-6630", "CVE-2016-6631", "CVE-2016-6632", "CVE-2016-6633");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-08 01:29:00 +0000 (Sun, 08 Jul 2018)");

  script_name("Mageia: Security Advisory (MGASA-2016-0291)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0291");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0291.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19204");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-29/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-30/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-32/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-33/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-34/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-35/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-36/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-37/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-38/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-39/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-41/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-42/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-43/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-45/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-46/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-47/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-48/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-49/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-50/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-51/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-52/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-53/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-54/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-55/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-56/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.4.15.6/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2016/8/16/phpmyadmin-401017-44158-and-464-are-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the MGASA-2016-0291 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In phpMyAdmin before 4.4.15.8, the decryption of the username/password is
vulnerable to a padding oracle attack. The can allow an attacker who has
access to a user's browser cookie file to decrypt the username and
password. Also, the same initialization vector (IV) is used to hash the
username and password stored in the phpMyAdmin cookie. If a user has the
same password as their username, an attacker who examines the browser
cookie can see that they are the same (CVE-2016-6606).

In phpMyAdmin before 4.4.15.8, multiple vulnerabilities have been
discovered in the following areas of phpMyAdmin: Zoom search, GIS editor,
Relation view, several Transformations, XML export, MediaWiki export,
Designer, when the MySQL server is running with a specially-crafted
log_bin directive, Database tab, Replication feature, and Database search
(CVE-2016-6607).

In phpMyAdmin before 4.4.15.8, a vulnerability was found where a specially
crafted database name could be used to run arbitrary PHP commands through
the array export feature (CVE-2016-6609).

In phpMyAdmin before 4.4.15.8, a full path disclosure vulnerability was
discovered where a user can trigger a particular error in the export
mechanism to discover the full path of phpMyAdmin on the disk
(CVE-2016-6610).

In phpMyAdmin before 4.4.15.8, a vulnerability was reported where a
specially crafted database and/or table name can be used to trigger an SQL
injection attack through the export functionality (CVE-2016-6611).

In phpMyAdmin before 4.4.15.8, a vulnerability was discovered where a user
can exploit the LOAD LOCAL INFILE functionality to expose files on the
server to the database system (CVE-2016-6612).

In phpMyAdmin before 4.4.15.8, a vulnerability was found where a user can
specially craft a symlink on disk, to a file which phpMyAdmin is permitted
to read but the user is not, which phpMyAdmin will then expose to the user
(CVE-2016-6613).

In phpMyAdmin before 4.4.15.8, a vulnerability was reported with the %u
username replacement functionality of the SaveDir and UploadDir features.
When the username substitution is configured, a specially-crafted user
name can be used to circumvent restrictions to traverse the file system
(CVE-2016-6614).

In phpMyAdmin before 4.4.15.8, multiple XSS vulnerabilities were found in
the following areas: Navigation pane and database/table hiding feature,
the 'Tracking' feature, and GIS visualization feature (CVE-2016-6615).

In phpMyAdmin before 4.4.15.8, a vulnerability was discovered in the
following features where a user can execute an SQL injection attack
against the account of the control user: User group Designer
(CVE-2016-6616).

In phpMyAdmin before 4.4.15.8, a vulnerability was found in the
transformation feature allowing a user to trigger a denial-of-service
(DOS) attack against the server (CVE-2016-6618).

In phpMyAdmin before 4.4.15.8, a vulnerability was discovered in the user
interface ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~4.4.15.8~1.mga5", rls:"MAGEIA5"))) {
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
