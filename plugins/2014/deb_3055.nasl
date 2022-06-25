# OpenVAS Vulnerability Test
# $Id: deb_3055.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 3055-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703055");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698");
  script_name("Debian Security Advisory DSA 3055-1 (pidgin - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-10-23 00:00:00 +0200 (Thu, 23 Oct 2014)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3055.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"pidgin on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 2.10.10-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 2.10.10-1.

We recommend that you upgrade your pidgin packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in Pidgin, a multi-protocol
instant messaging client:

CVE-2014-3694
It was discovered that the SSL/TLS plugins failed to validate the
basic constraints extension in intermediate CA certificates.

CVE-2014-3695
Yves Younan and Richard Johnson discovered that emotictons with
overly large length values could crash Pidgin.

CVE-2014-3696
Yves Younan and Richard Johnson discovered that malformed Groupwise
messages could crash Pidgin.

CVE-2014-3698
Thijs Alkemade and Paul Aurich discovered that malformed XMPP
messages could result in memory disclosure.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"finch", ver:"2.10.10-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"finch-dev", ver:"2.10.10-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.10.10-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.10.10-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpurple0", ver:"2.10.10-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin", ver:"2.10.10-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.10.10-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.10.10-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.10.10-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}