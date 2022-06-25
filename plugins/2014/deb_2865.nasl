# OpenVAS Vulnerability Test
# $Id: deb_2865.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2865-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702865");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-0067");
  script_name("Debian Security Advisory DSA 2865-1 (postgresql-9.1 - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-20 00:00:00 +0100 (Thu, 20 Feb 2014)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2865.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"postgresql-9.1 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 9.1_9.1.12-0wheezy1.

For the unstable distribution (sid), these problems have been fixed in
version 9.3.3-1 of the postgresql-9.3 package.

We recommend that you upgrade your postgresql-9.1 packages.");
  script_tag(name:"summary", value:"Various vulnerabilities were discovered in PostgreSQL:

CVE-2014-0060 Shore up GRANT ... WITH ADMIN OPTION restrictions (Noah Misch)

Granting a role without ADMIN OPTION is supposed to prevent the grantee
from adding or removing members from the granted role, but this
restriction was easily bypassed by doing SET ROLE first. The security
impact is mostly that a role member can revoke the access of others,
contrary to the wishes of his grantor. Unapproved role member additions
are a lesser concern, since an uncooperative role member could provide
most of his rights to others anyway by creating views or SECURITY
DEFINER functions.

Description truncated. Please see the references for more information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecpg6", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpq-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpq5", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-9.1-dbg", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-client-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-contrib-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-doc-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plperl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plpython-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plpython3-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-pltcl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-server-dev-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}