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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2009.1964");
  script_cve_id("CVE-2009-4034", "CVE-2009-4136");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1964)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1964");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1964");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-7.4, postgresql-8.1, postgresql-8.3' package(s) announced via the DSA-1964 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in PostgreSQL, a database server. The Common Vulnerabilities and Exposures project identifies the following problems:

It was discovered that PostgreSQL did not properly verify the Common Name attribute in X.509 certificates, enabling attackers to bypass the (optional) TLS protection on client-server connections, by relying on a certificate from a trusted CA which contains an embedded NUL byte in the Common Name (CVE-2009-4034).

Authenticated database users could elevate their privileges by creating specially-crafted index functions (CVE-2009-4136).

The following matrix shows fixed source package versions for the respective distributions.

oldstable/etch stable/lenny testing/unstable

postgresql-7.4 7.4.27-0etch1

postgresql-8.1 8.1.19-0etch1

postgresql-8.3 8.3.9-0lenny1 8.3.9-1

postgresql-8.4 8.4.2-1

In addition to these security fixes, the updates contain reliability improvements and fix other defects.

We recommend that you upgrade your PostgreSQL packages.");

  script_tag(name:"affected", value:"'postgresql-7.4, postgresql-8.1, postgresql-8.3' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-compat2", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg5", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtypes2", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq-dev", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq4", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-7.4", ver:"1:7.4.27-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.1", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-7.4", ver:"1:7.4.27-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-8.1", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-7.4", ver:"1:7.4.27-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-8.1", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-7.4", ver:"1:7.4.27-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-8.1", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-7.4", ver:"1:7.4.27-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-8.1", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython-7.4", ver:"1:7.4.27-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython-8.1", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-7.4", ver:"1:7.4.27-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-8.1", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-7.4", ver:"1:7.4.27-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-8.1", ver:"8.1.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-compat3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg6", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtypes3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq-dev", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq5", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-8.3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-8.3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-8.3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-8.3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython-8.3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-8.3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-8.3", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql", ver:"8.3.9-0lenny1", rls:"DEB5"))) {
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
