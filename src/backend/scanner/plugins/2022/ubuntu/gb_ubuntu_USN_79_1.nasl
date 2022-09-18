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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.79.1");
  script_cve_id("CVE-2005-0244", "CVE-2005-0245", "CVE-2005-0246", "CVE-2005-0247");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-79-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-79-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-79-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql' package(s) announced via the USN-79-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The execution of custom PostgreSQL functions can be restricted with
the EXECUTE privilege. However, previous versions did not check this
privilege when executing a function which was part of an aggregate.
As a result, any database user could circumvent the EXECUTE restriction of
functions with a particular (but very common) parameter structure by
creating an aggregate wrapper around the function. (CAN-2005-0244)

Several buffer overflows have been discovered in the SQL parser. These
could be exploited by any database user to crash the PostgreSQL server
or execute arbitrary code with the privileges of the server.
(CAN-2005-0245, CAN-2005-0247)

Finally, this update fixes a Denial of Service vulnerability of the
contributed 'intagg' module. By constructing specially crafted arrays,
a database user was able to corrupt and crash the PostgreSQL server.
(CAN-2005-0246). Please note that this module is part of the
'postgresql-contrib' package, which is not officially supported by
Ubuntu.");

  script_tag(name:"affected", value:"'postgresql' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg4", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtcl-dev", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtcl", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq3", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-dev", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql", ver:"7.4.5-3ubuntu0.4", rls:"UBUNTU4.10"))) {
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
