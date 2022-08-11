# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704441");
  script_version("2019-05-27T07:36:21+0000");
  script_cve_id("CVE-2018-14773", "CVE-2018-19789", "CVE-2018-19790", "CVE-2019-10909", "CVE-2019-10910", "CVE-2019-10911", "CVE-2019-10912", "CVE-2019-10913");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-27 07:36:21 +0000 (Mon, 27 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-11 02:00:17 +0000 (Sat, 11 May 2019)");
  script_name("Debian Security Advisory DSA 4441-1 (symfony - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4441.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4441-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'symfony'
  package(s) announced via the DSA-4441-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the Symfony PHP framework
which could lead to cache bypass, authentication bypass, information
disclosure, open redirect, cross-site request forgery, deletion of
arbitrary files, or arbitrary code execution.");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 2.8.7+dfsg-1.3+deb9u2.

We recommend that you upgrade your symfony packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"php-symfony", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-asset", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-browser-kit", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-class-loader", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-config", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-console", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-css-selector", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug-bundle", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dependency-injection", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-doctrine-bridge", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dom-crawler", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-event-dispatcher", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-expression-language", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-filesystem", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-finder", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-form", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-framework-bundle", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-foundation", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-kernel", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-intl", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-ldap", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-locale", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-monolog-bridge", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-options-resolver", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-phpunit-bridge", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-process", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-access", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-info", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-proxy-manager-bridge", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-routing", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-bundle", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-core", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-csrf", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-guard", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-http", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-serializer", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-stopwatch", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-swiftmailer-bridge", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-templating", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-translation", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bridge", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bundle", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-validator", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-var-dumper", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-profiler-bundle", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-yaml", ver:"2.8.7+dfsg-1.3+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);