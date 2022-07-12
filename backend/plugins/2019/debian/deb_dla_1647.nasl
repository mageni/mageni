###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1647.nasl 14282 2019-03-18 14:55:18Z cfischer $
#
# Auto-generated from advisory DLA 1647-1 using nvtgen 1.0
# Script version: 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891647");
  script_version("$Revision: 14282 $");
  script_cve_id("CVE-2018-17199");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1647-1] apache2 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:55:18 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-01-30 00:00:00 +0100 (Wed, 30 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00024.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"apache2 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
2.4.10-10+deb8u13.

We recommend that you upgrade your apache2 packages.");
  script_tag(name:"summary", value:"Diego Angulo from ImExHS discovered an issue in the webserver apache2.
The module mod_session ignored the expiry time of sessions handled by
mod_session_cookie, because the expiry time is available only after
decoding the session and the check was already done before.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"apache2", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-data", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dev", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-pristine", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-macro", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-proxy-html", ver:"2.4.10-10+deb8u13", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}