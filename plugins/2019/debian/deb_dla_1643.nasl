###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1643.nasl 14282 2019-03-18 14:55:18Z cfischer $
#
# Auto-generated from advisory DLA 1643-1 using nvtgen 1.0
# Script version: 1.1
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.891643");
  script_version("$Revision: 14282 $");
  script_cve_id("CVE-2018-20217", "CVE-2018-5729", "CVE-2018-5730");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1643-1] krb5 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:55:18 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-01-28 00:00:00 +0100 (Mon, 28 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"krb5 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie',
these problems have been fixed in version 1.12.1+dfsg-19+deb8u5.

We recommend that you upgrade your krb5 packages.");
  script_tag(name:"summary", value:"krb5, a MIT Kerberos implementation, had several flaws in LDAP DN
checking, which could be used to circumvent a DN containership check by
supplying special parameters to some calls.

Further an attacker could crash the KDC by making S4U2Self requests.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-gss-samples", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-locales", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-otp", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit9", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit9", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-7", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrad-dev", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrad0", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.12.1+dfsg-19+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}