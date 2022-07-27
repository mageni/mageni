# OpenVAS Vulnerability Test
# $Id: deb_2736.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2736-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.892736");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-4852", "CVE-2011-4607", "CVE-2013-4206", "CVE-2013-4208", "CVE-2013-4207");
  script_name("Debian Security Advisory DSA 2736-1 (putty - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-08-11 00:00:00 +0200 (Sun, 11 Aug 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2736.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"putty on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 0.60+2010-02-20-1+squeeze2. This update also provides a fix for
CVE-2011-4607
, which was fixed for stable already.

For the stable distribution (wheezy), these problems have been fixed in
version 0.62-9+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 0.63-1.

We recommend that you upgrade your putty packages.");
  script_tag(name:"summary", value:"Several vulnerabilities where discovered in PuTTY, a Telnet/SSH client
for X. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2013-4206
Mark Wooding discovered a heap-corrupting buffer underrun bug in the
modmul function which performs modular multiplication. As the modmul
function is called during validation of any DSA signature received
by PuTTY, including during the initial key exchange phase, a
malicious server could exploit this vulnerability before the client
has received and verified a host key signature. An attack to this
vulnerability can thus be performed by a man-in-the-middle between
the SSH client and server, and the normal host key protections
against man-in-the-middle attacks are bypassed.

CVE-2013-4207
It was discovered that non-coprime values in DSA signatures can
cause a buffer overflow in the calculation code of modular inverses
when verifying a DSA signature. Such a signature is invalid. This
bug however applies to any DSA signature received by PuTTY,
including during the initial key exchange phase and thus it can be
exploited by a malicious server before the client has received and
verified a host key signature.

CVE-2013-4208
It was discovered that private keys were left in memory after being
used by PuTTY tools.

CVE-2013-4852
Gergely Eberhardt from SEARCH-LAB Ltd. discovered that PuTTY is
vulnerable to an integer overflow leading to heap overflow during
the SSH handshake before authentication due to improper bounds
checking of the length parameter received from the SSH server. A
remote attacker could use this vulnerability to mount a local denial
of service attack by crashing the putty client.

Additionally this update backports some general proactive potentially
security-relevant tightening from upstream.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"pterm", ver:"0.60+2010-02-20-1+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"putty", ver:"0.60+2010-02-20-1+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"putty-doc", ver:"0.60+2010-02-20-1+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"putty-tools", ver:"0.60+2010-02-20-1+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pterm", ver:"0.62-9+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"putty", ver:"0.62-9+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"putty-doc", ver:"0.62-9+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"putty-tools", ver:"0.62-9+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}