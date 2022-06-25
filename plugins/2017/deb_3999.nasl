###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_3999.nasl 14275 2019-03-18 14:39:45Z cfischer $
#
# Auto-generated from advisory DSA 3999-1 using nvtgen 1.0
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
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703999");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088");
  script_name("Debian Security Advisory DSA 3999-1 (wpa - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-10-16 00:00:00 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3999.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9|10)");
  script_tag(name:"affected", value:"wpa on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 2.3-1+deb8u5.

For the stable distribution (stretch), these problems have been fixed in
version 2:2.4-1+deb9u1.

For the testing distribution (buster), these problems have been fixed
in version 2:2.4-1.1.

For the unstable distribution (sid), these problems have been fixed in
version 2:2.4-1.1.

We recommend that you upgrade your wpa packages.");
  script_tag(name:"summary", value:"Mathy Vanhoef of the imec-DistriNet research group of KU Leuven discovered
multiple vulnerabilities in the WPA protocol, used for authentication in
wireless networks. Those vulnerabilities applies to both the access point
(implemented in hostapd) and the station (implemented in wpa_supplicant).

An attacker exploiting the vulnerabilities could force the vulnerable system to
reuse cryptographic session keys, enabling a range of cryptographic attacks
against the ciphers used in WPA1 and WPA2.

More information can be found in the researchers's paper, Key Reinstallation Attacks:
Forcing Nonce Reuse in WPA2
.

CVE-2017-13077:

reinstallation of the pairwise key in the Four-way handshake

CVE-2017-13078:

reinstallation of the group key in the Four-way handshake

CVE-2017-13079:

reinstallation of the integrity group key in the Four-way
handshake

CVE-2017-13080:

reinstallation of the group key in the Group Key handshake

CVE-2017-13081:

reinstallation of the integrity group key in the Group Key
handshake

CVE-2017-13082:

accepting a retransmitted Fast BSS Transition Reassociation Request
and reinstalling the pairwise key while processing it

CVE-2017-13086:

reinstallation of the Tunneled Direct-Link Setup (TDLS) PeerKey
(TPK) key in the TDLS handshake

CVE-2017-13087:

reinstallation of the group key (GTK) when processing a
Wireless Network Management (WNM) Sleep Mode Response frame

CVE-2017-13088:

reinstallation of the integrity group key (IGTK) when processing
a Wireless Network Management (WNM) Sleep Mode Response frame");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"hostapd", ver:"2.3-1+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wpagui", ver:"2.3-1+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wpasupplicant", ver:"2.3-1+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hostapd", ver:"2:2.4-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wpagui", ver:"2:2.4-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wpasupplicant", ver:"2:2.4-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hostapd", ver:"2:2.4-1.1", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wpagui", ver:"2:2.4-1.1", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wpasupplicant", ver:"2:2.4-1.1", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wpasupplicant-udeb", ver:"2:2.4-1.1", rls:"DEB10")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}