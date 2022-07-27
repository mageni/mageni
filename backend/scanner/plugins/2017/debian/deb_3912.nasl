# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3912-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.703912");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2017-11103");
  script_name("Debian Security Advisory DSA 3912-1 (heimdal - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2017-07-16 00:00:00 +0200 (Sun, 16 Jul 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3912.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"heimdal on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has been fixed
in version 1.6~rc2+dfsg-9+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 7.1.0+dfsg-13+deb9u1.

For the unstable distribution (sid), this problem has been fixed in
version 7.4.0.dfsg.1-1.

We recommend that you upgrade your heimdal packages.");
  script_tag(name:"summary", value:"Jeffrey Altman, Viktor Dukhovni, and Nicolas Williams reported that
Heimdal, an implementation of Kerberos 5 that aims to be compatible with
MIT Kerberos, trusts metadata taken from the unauthenticated plaintext
(Ticket), rather than the authenticated and encrypted KDC response. A
man-in-the-middle attacker can use this flaw to impersonate services to
the client.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"heimdal-clients", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-dbg", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-dev", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-docs", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-kcm", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-kdc", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-multidev", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-servers", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libhcrypto4-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libheimbase1-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libheimntlm0-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt7-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv8-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libroken18-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwind0-heimdal", ver:"7.1.0+dfsg-13+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-clients", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-clients-x", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-dbg", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-dev", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-docs", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-kcm", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-kdc", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-multidev", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-servers", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-servers-x", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libhcrypto4-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libheimbase1-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libheimntlm0-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt7-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv8-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libroken18-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwind0-heimdal", ver:"1.6~rc2+dfsg-9+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}