###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4309.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4309-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.704309");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-16151", "CVE-2018-17540");
  script_name("Debian Security Advisory DSA 4309-1 (strongswan - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-01 00:00:00 +0200 (Mon, 01 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4309.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"strongswan on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 5.5.1-4+deb9u4.

We recommend that you upgrade your strongswan packages.

For the detailed security status of strongswan please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/strongswan");
  script_tag(name:"summary", value:"Google's OSS-Fuzz revealed an exploitable bug in the gmp plugin caused by the
patch that fixes CVE-2018-16151 and CVE-2018-16151
(DSA-4305-1).

An attacker could trigger it using crafted certificates with RSA keys with
very small moduli. Verifying signatures with such keys would cause an integer
underflow and subsequent heap buffer overflow resulting in a crash of the
daemon. While arbitrary code execution is not completely ruled out because of
the heap buffer overflow, due to the form of the data written to the buffer
it seems difficult to actually exploit it in such a way.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"charon-cmd", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"charon-systemd", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcharon-extra-plugins", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan-extra-plugins", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan-standard-plugins", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-charon", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ike", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-libcharon", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-nm", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-pki", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-scepclient", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-starter", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-swanctl", ver:"5.5.1-4+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}