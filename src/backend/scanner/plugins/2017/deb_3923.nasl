# OpenVAS Vulnerability Test
# $Id: deb_3923.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3923-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703923");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839");
  script_name("Debian Security Advisory DSA 3923-1 (freerdp - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-08-01 00:00:00 +0200 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3923.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"freerdp on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.1.0~git20140921.1.440916e+dfsg1-14.

We recommend that you upgrade your freerdp packages.");
  script_tag(name:"summary", value:"Tyler Bohan of Talos discovered that FreeRDP, a free implementation of
the Remote Desktop Protocol (RDP), contained several vulnerabilities
that allowed a malicious remote server or a man-in-the-middle to
either cause a DoS by forcibly terminating the client, or execute
arbitrary code on the client side.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"freerdp-x11", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"freerdp-x11-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-cache1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-codec1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-common1.1.0", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-core1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-crypto1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-gdi1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-locale1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-plugins-standard", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-plugins-standard-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-primitives1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-rail1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-utils1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-asn1-0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-bcrypt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-credentials0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-credui0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-crt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-crypto0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-dsparse0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-environment0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-error0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-file0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-handle0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-heap0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-input0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-interlocked0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-io0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-library0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-path0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-pipe0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-pool0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-registry0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-rpc0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-sspi0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-sspicli0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-synch0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-sysinfo0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-thread0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-timezone0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-utils0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-winhttp0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-winsock0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxfreerdp-client-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"freerdp-x11", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"freerdp-x11-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-cache1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-codec1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-common1.1.0", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-core1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-crypto1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-gdi1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-locale1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-plugins-standard", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-plugins-standard-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-primitives1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-rail1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreerdp-utils1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-asn1-0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-bcrypt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-credentials0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-credui0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-crt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-crypto0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-dsparse0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-environment0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-error0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-file0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-handle0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-heap0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-input0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-interlocked0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-io0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-library0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-path0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-pipe0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-pool0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-registry0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-rpc0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-sspi0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-sspicli0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-synch0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-sysinfo0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-thread0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-timezone0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-utils0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-winhttp0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwinpr-winsock0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxfreerdp-client-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}