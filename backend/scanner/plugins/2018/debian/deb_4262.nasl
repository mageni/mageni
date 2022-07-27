###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4262.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DSA 4262-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704262");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2016-2403", "CVE-2017-1665", "CVE-2017-16653", "CVE-2017-16654", "CVE-2017-16790",
                "CVE-2018-11385", "CVE-2018-11386", "CVE-2018-11406");
  script_name("Debian Security Advisory DSA 4262-1 (symfony - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-03 00:00:00 +0200 (Fri, 03 Aug 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4262.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"symfony on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 2.8.7+dfsg-1.3+deb9u1.

We recommend that you upgrade your symfony packages.

For the detailed security status of symfony please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/symfony");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been found in the Symfony PHP framework
which could lead to open redirects, cross-site request forgery,
information disclosure, session fixation or denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"php-symfony", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-asset", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-browser-kit", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-class-loader", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-config", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-console", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-css-selector", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-debug", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-debug-bundle", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-dependency-injection", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-doctrine-bridge", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-dom-crawler", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-event-dispatcher", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-expression-language", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-filesystem", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-finder", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-form", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-framework-bundle", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-http-foundation", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-http-kernel", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-intl", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-ldap", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-locale", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-monolog-bridge", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-options-resolver", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-phpunit-bridge", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-process", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-property-access", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-property-info", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-proxy-manager-bridge", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-routing", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-security", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-security-bundle", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-security-core", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-security-csrf", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-security-guard", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-security-http", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-serializer", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-stopwatch", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-swiftmailer-bridge", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-templating", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-translation", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-twig-bridge", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-twig-bundle", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-validator", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-var-dumper", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-web-profiler-bundle", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php-symfony-yaml", ver:"2.8.7+dfsg-1.3+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}