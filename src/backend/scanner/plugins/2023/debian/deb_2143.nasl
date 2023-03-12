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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2011.2143");
  script_cve_id("CVE-2010-3677", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3840");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2143)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2143");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2143");
  script_xref(name:"URL", value:"https://www.debian.org/security/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-5.0' package(s) announced via the DSA-2143 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the MySQL database server. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-3677

It was discovered that MySQL allows remote authenticated users to cause a denial of service (mysqld daemon crash) via a join query that uses a table with a unique SET column.

CVE-2010-3680

It was discovered that MySQL allows remote authenticated users to cause a denial of service (mysqld daemon crash) by creating temporary tables while using InnoDB, which triggers an assertion failure.

CVE-2010-3681

It was discovered that MySQL allows remote authenticated users to cause a denial of service (mysqld daemon crash) by using the HANDLER interface and performing 'alternate reads from two indexes on a table,' which triggers an assertion failure.

CVE-2010-3682

It was discovered that MySQL incorrectly handled use of EXPLAIN with certain queries. An authenticated user could crash the server.

CVE-2010-3833

It was discovered that MySQL incorrectly handled propagation during evaluation of arguments to extreme-value functions. An authenticated user could crash the server.

CVE-2010-3834

It was discovered that MySQL incorrectly handled materializing a derived table that required a temporary table for grouping. An authenticated user could crash the server.

CVE-2010-3835

It was discovered that MySQL incorrectly handled certain user-variable assignment expressions that are evaluated in a logical expression context. An authenticated user could crash the server.

CVE-2010-3836

It was discovered that MySQL incorrectly handled pre-evaluation of LIKE predicates during view preparation. An authenticated user could crash the server.

CVE-2010-3837

It was discovered that MySQL incorrectly handled using GROUP_CONCAT() and WITH ROLLUP together. An authenticated user could crash the server.

CVE-2010-3838

It was discovered that MySQL incorrectly handled certain queries using a mixed list of numeric and LONGBLOB arguments to the GREATEST() or LEAST() functions. An authenticated user could crash the server.

CVE-2010-3840

It was discovered that MySQL incorrectly handled improper WKB data passed to the PolyFromWKB() function. An authenticated user could crash the server.

For the stable distribution (lenny), these problems have been fixed in version 5.0.51a-24+lenny5.

The testing (squeeze) and unstable (sid) distribution do not contain mysql-dfsg-5.0 anymore.

We recommend that you upgrade your mysql-dfsg-5.0 packages.

Further information about Debian Security Advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.51a-24+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.51a-24+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.51a-24+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.51a-24+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.51a-24+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.51a-24+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.51a-24+lenny5", rls:"DEB5"))) {
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
