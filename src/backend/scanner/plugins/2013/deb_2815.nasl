# OpenVAS Vulnerability Test
# $Id: deb_2815.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2815-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.892815");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-6359", "CVE-2013-6048");
  script_name("Debian Security Advisory DSA 2815-1 (munin - denial of service)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-12-09 00:00:00 +0100 (Mon, 09 Dec 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2815.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"munin on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 2.0.6-4+deb7u2.

For the testing distribution (jessie), these problems have been fixed in
version 2.0.18-1.

For the unstable distribution (sid), these problems have been fixed in
version 2.0.18-1.

We recommend that you upgrade your munin packages.");
  script_tag(name:"summary", value:"Christoph Biedl discovered two denial of service vulnerabilities in
munin, a network-wide graphing framework. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2013-6048
The Munin::Master::Node module of munin does not properly validate
certain data a node sends. A malicious node might exploit this to
drive the munin-html process into an infinite loop with memory
exhaustion on the munin master.

CVE-2013-6359A malicious node, with a plugin enabled using multigraph
as a
multigraph service name, can abort data collection for the entire
node the plugin runs on.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"munin", ver:"2.0.6-4+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"munin-async", ver:"2.0.6-4+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"munin-common", ver:"2.0.6-4+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"munin-doc", ver:"2.0.6-4+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"munin-node", ver:"2.0.6-4+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"munin-plugins-core", ver:"2.0.6-4+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"munin-plugins-extra", ver:"2.0.6-4+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"munin-plugins-java", ver:"2.0.6-4+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}