# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.892154");
  script_version("2020-03-23T04:00:10+0000");
  script_cve_id("CVE-2020-10802", "CVE-2020-10803");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-03-23 09:09:57 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-23 04:00:10 +0000 (Mon, 23 Mar 2020)");
  script_name("Debian LTS: Security Advisory for phpmyadmin (DLA-2154-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00028.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2154-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/954665");
  script_xref(name:"URL", value:"https://bugs.debian.org/954666");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin'
  package(s) announced via the DLA-2154-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following packages CVE(s) were reported against phpmyadmin.

CVE-2020-10802

In phpMyAdmin 4.x before 4.9.5, a SQL injection vulnerability
has been discovered where certain parameters are not properly
escaped when generating certain queries for search actions in
libraries/classes/Controllers/Table/TableSearchController.php.
An attacker can generate a crafted database or table name. The
attack can be performed if a user attempts certain search
operations on the malicious database or table.

CVE-2020-10803

In phpMyAdmin 4.x before 4.9.5, a SQL injection vulnerability
was discovered where malicious code could be used to trigger
an XSS attack through retrieving and displaying results (in
tbl_get_field.php and libraries/classes/Display/Results.php).
The attacker must be able to insert crafted data into certain
database tables, which when retrieved (for instance, through the
Browse tab) can trigger the XSS attack.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4:4.2.12-2+deb8u9.

We recommend that you upgrade your phpmyadmin packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.2.12-2+deb8u9", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
