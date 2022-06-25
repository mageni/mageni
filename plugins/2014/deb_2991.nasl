# OpenVAS Vulnerability Test
# $Id: deb_2991.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2991-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702991");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2013-5705");
  script_name("Debian Security Advisory DSA 2991-1 (modsecurity-apache - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-07-27 00:00:00 +0200 (Sun, 27 Jul 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2991.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"modsecurity-apache on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), this problem has been fixed in
version 2.6.6-6+deb7u2.

For the testing distribution (jessie), this problem has been fixed in
version 2.7.7-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.7.7-1.

We recommend that you upgrade your modsecurity-apache packages.");
  script_tag(name:"summary", value:"Martin Holst Swende discovered a flaw in the way chunked requests are
handled in ModSecurity, an Apache module whose purpose is to tighten the
Web application security. A remote attacker could use this flaw to
bypass intended mod_security restrictions by using chunked transfer
coding with a capitalized Chunked value in the Transfer-Encoding HTTP
header, allowing to send requests containing content that should have
been removed by mod_security.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache-mod-security", ver:"2.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-modsecurity", ver:"2.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}