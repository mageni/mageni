# OpenVAS Vulnerability Test
# $Id: deb_3203.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3203-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703203");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-2688", "CVE-2015-2689");
  script_name("Debian Security Advisory DSA 3203-1 (tor - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-22 00:00:00 +0100 (Sun, 22 Mar 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3203.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"tor on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 0.2.4.26-1.

For the testing distribution (jessie) and unstable distribution (sid),
these problems have been fixed in version 0.2.5.11-1.

Furthermore, this update disables support for SSLv3 in Tor. All
versions of OpenSSL in use with Tor today support TLS 1.0 or later.

Additionally, this release updates the geoIP database used by Tor as
well as the list of directory authority servers, which Tor clients use
to bootstrap and who sign the Tor directory consensus document.

We recommend that you upgrade your tor packages.");
  script_tag(name:"summary", value:"Several denial-of-service issues have
been discovered in Tor, a connection-based low-latency anonymous communication
system.

Jowr discovered that very high DNS query load on a relay could
trigger an assertion error.

A relay could crash with an assertion error if a buffer of exactly
the wrong layout was passed to buf_pullup() at exactly the wrong
time.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tor", ver:"0.2.4.26-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-dbg", ver:"0.2.4.26-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-geoipdb", ver:"0.2.4.26-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}