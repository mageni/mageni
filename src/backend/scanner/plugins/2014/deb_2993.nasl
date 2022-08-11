# OpenVAS Vulnerability Test
# $Id: deb_2993.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2993-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702993");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-5117");
  script_name("Debian Security Advisory DSA 2993-1 (tor - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-07-31 00:00:00 +0200 (Thu, 31 Jul 2014)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2993.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"tor on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 0.2.4.23-1~deb7u1.

For the testing distribution (jessie) and the unstable distribution
(sid), these problems have been fixed in version 0.2.4.23-1.

For the experimental distribution, these problems have been fixed in
version 0.2.5.6-alpha-1.

We recommend that you upgrade your tor packages.");
  script_tag(name:"summary", value:"Several issues have been discovered in Tor, a connection-based
low-latency anonymous communication system, resulting in information
leaks.

Relay-early cells could be used by colluding relays on the network to
tag user circuits and so deploy traffic confirmation attacks
[CVE-2014-5117
]. The updated version emits a warning and drops the
circuit upon receiving inbound relay-early cells, preventing this
specific kind of attack.

A bug in the bounds-checking in the 32-bit curve25519-donna
implementation could cause incorrect results on 32-bit
implementations when certain malformed inputs were used along with a
small class of private ntor keys. This flaw does not currently
appear to allow an attacker to learn private keys or impersonate a
Tor server, but it could provide a means to distinguish 32-bit Tor
implementations from 64-bit Tor implementations.

The following additional security-related improvements have been
implemented:

As a client, the new version will effectively stop using CREATE_FAST
cells. While this adds computational load on the network, this
approach can improve security on connections where Tor's circuit
handshake is stronger than the available TLS connection security
levels.

Prepare clients to use fewer entry guards by honoring the consensus
parameters.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tor", ver:"0.2.4.23-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-dbg", ver:"0.2.4.23-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-geoipdb", ver:"0.2.4.23-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}