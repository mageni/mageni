# OpenVAS Vulnerability Test
# $Id: deb_2614.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2614-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.892614");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2012-5964", "CVE-2012-5962", "CVE-2012-5961", "CVE-2012-5959", "CVE-2012-5965", "CVE-2012-5963", "CVE-2012-5960", "CVE-2012-5958");
  script_name("Debian Security Advisory DSA 2614-1 (libupnp - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-02-01 00:00:00 +0100 (Fri, 01 Feb 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2614.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"libupnp on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), these problems have been fixed in
version 1:1.6.6-5+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in
version 1:1.6.17-1.2.

For the unstable distribution (sid), these problems have been fixed in
version 1:1.6.17-1.2.

We recommend that you upgrade your libupnp packages.");
  script_tag(name:"summary", value:"Multiple stack-based buffer overflows were discovered in libupnp, a library
used for handling the Universal Plug and Play protocol. HD Moore from Rapid7
discovered that SSDP queries where not correctly handled by the
unique_service_name() function.

An attacker sending carefully crafted SSDP queries to a daemon built on libupnp
could generate a buffer overflow, overwriting the stack, leading to the daemon
crash and possible remote code execution.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libupnp-dev", ver:"1:1.6.6-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libupnp3", ver:"1:1.6.6-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libupnp3-dbg", ver:"1:1.6.6-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libupnp3-dev", ver:"1:1.6.6-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libupnp-dev", ver:"1:1.6.17-1.2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libupnp6", ver:"1:1.6.17-1.2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libupnp6-dbg", ver:"1:1.6.17-1.2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libupnp6-dev", ver:"1:1.6.17-1.2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libupnp6-doc", ver:"1:1.6.17-1.2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}