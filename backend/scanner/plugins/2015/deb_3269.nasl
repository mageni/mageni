# OpenVAS Vulnerability Test
# $Id: deb_3269.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3269-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703269");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_name("Debian Security Advisory DSA 3269-1 (postgresql-9.1 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-05-22 00:00:00 +0200 (Fri, 22 May 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3269.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"postgresql-9.1 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), these problems have been fixed
in version 9.1.16-0+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 9.1.16-0+deb8u1. (Jessie contains a reduced postgresql-9.1
package, only CVE-2015-3166
is fixed in the produced binary package
postgresql-plperl-9.1. We recommend to upgrade to postgresql-9.4 to get
the full set of fixes. See the Jessie release notes for details.)

The testing distribution (stretch) and the unstable distribution (sid)
do not contain the postgresql-9.1 package.

We recommend that you upgrade your postgresql-9.1 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been found in PostgreSQL-9.1, a SQL
database system.

CVE-2015-3165

(Remote crash)

SSL clients disconnecting just before the authentication timeout
expires can cause the server to crash.

CVE-2015-3166

(Information exposure)

The replacement implementation of snprintf() failed to check for
errors reported by the underlying system library calls, the main
case that might be missed is out-of-memory situations. In the worst
case this might lead to information exposure.

CVE-2015-3167

(Possible side-channel key exposure)

In contrib/pgcrypto, some cases of decryption with an incorrect key
could report other error message texts. Fix by using a
one-size-fits-all message.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecpg6", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpq-dev", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpq5", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-9.1-dbg", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-client-9.1", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-contrib-9.1", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-doc-9.1", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plperl-9.1", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plpython-9.1", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plpython3-9.1", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-pltcl-9.1", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-server-dev-9.1", ver:"9.1.16-0+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}