# OpenVAS Vulnerability Test
# $Id: deb_3097.nasl 14277 2019-03-18 14:45:38Z cfischer $
# Auto-generated from advisory DSA 3097-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703097");
  script_version("$Revision: 14277 $");
  script_cve_id("CVE-2014-8602");
  script_name("Debian Security Advisory DSA 3097-1 (unbound - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-12-10 00:00:00 +0100 (Wed, 10 Dec 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3097.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"unbound on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), this
problem has been fixed in version 1.4.17-3+deb7u2.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 1.4.22-3.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.22-3.

We recommend that you upgrade your unbound packages.");
  script_tag(name:"summary", value:"Florian Maury from ANSSI discovered that
unbound, a validating, recursive, and caching DNS resolver, was prone to a denial
of service vulnerability. An attacker crafting a malicious zone and able to emit
(or make emit) queries to the server can trick the resolver into
following an endless series of delegations, leading to resource
exhaustion and huge network usage.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libunbound-dev", ver:"1.4.17-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libunbound2", ver:"1.4.17-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-unbound", ver:"1.4.17-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"unbound", ver:"1.4.17-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"unbound-anchor", ver:"1.4.17-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"unbound-host", ver:"1.4.17-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}