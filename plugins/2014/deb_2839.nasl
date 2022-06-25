# OpenVAS Vulnerability Test
# $Id: deb_2839.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2839-1 using nvtgen 1.0
# Script version: 1.2
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
  script_oid("1.3.6.1.4.1.25623.1.0.702839");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2013-4130", "CVE-2013-4282");
  script_name("Debian Security Advisory DSA 2839-1 (spice - denial of service)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-08 00:00:00 +0100 (Wed, 08 Jan 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2839.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"spice on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 0.11.0-1+deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 0.12.4-0nocelt2.

For the unstable distribution (sid), these problems have been fixed in
version 0.12.4-0nocelt2.

We recommend that you upgrade your spice packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been found in spice, a SPICE protocol
client and server library. The Common Vulnerabilities and Exposures
project identifies the following issues:

CVE-2013-4130
David Gibson of Red Hat discovered that SPICE incorrectly handled
certain network errors. A remote user able to initiate a SPICE
connection to an application acting as a SPICE server could use this
flaw to crash the application.

CVE-2013-4282
Tomas Jamrisko of Red Hat discovered that SPICE incorrectly handled
long passwords in SPICE tickets. A remote user able to initiate a
SPICE connection to an application acting as a SPICE server could use
this flaw to crash the application.

Applications acting as a SPICE server must be restarted for this update
to take effect.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libspice-server-dev", ver:"0.11.0-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libspice-server1", ver:"0.11.0-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"spice-client", ver:"0.11.0-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}