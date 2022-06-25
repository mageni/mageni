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
  script_oid("1.3.6.1.4.1.25623.1.0.704573");
  script_version("2019-11-20T03:00:09+0000");
  script_cve_id("CVE-2019-18887", "CVE-2019-18888", "CVE-2019-18889");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-11-20 03:00:09 +0000 (Wed, 20 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-20 03:00:09 +0000 (Wed, 20 Nov 2019)");
  script_name("Debian Security Advisory DSA 4573-1 (symfony - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4573.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4573-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'symfony'
  package(s) announced via the DSA-4573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in the Symfony PHP framework
which could lead to a timing attack/information leak, argument injection
and code execution via unserialization.");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), these problems have been fixed
in version 2.8.7+dfsg-1.3+deb9u3.

For the stable distribution (buster), these problems have been fixed in
version 3.4.22+dfsg-2+deb10u1.

We recommend that you upgrade your symfony packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"php-symfony", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-asset", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-browser-kit", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-class-loader", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-config", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-console", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-css-selector", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug-bundle", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dependency-injection", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-doctrine-bridge", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dom-crawler", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-event-dispatcher", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-expression-language", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-filesystem", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-finder", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-form", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-framework-bundle", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-foundation", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-kernel", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-intl", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-ldap", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-locale", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-monolog-bridge", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-options-resolver", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-phpunit-bridge", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-process", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-access", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-info", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-proxy-manager-bridge", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-routing", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-bundle", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-core", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-csrf", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-guard", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-http", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-serializer", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-stopwatch", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-swiftmailer-bridge", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-templating", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-translation", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bridge", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bundle", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-validator", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-var-dumper", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-profiler-bundle", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-yaml", ver:"2.8.7+dfsg-1.3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-asset", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-browser-kit", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-cache", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-class-loader", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-config", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-console", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-css-selector", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug-bundle", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dependency-injection", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-doctrine-bridge", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dom-crawler", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dotenv", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-event-dispatcher", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-expression-language", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-filesystem", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-finder", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-form", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-framework-bundle", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-foundation", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-kernel", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-inflector", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-intl", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-ldap", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-lock", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-monolog-bridge", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-options-resolver", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-phpunit-bridge", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-process", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-access", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-info", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-proxy-manager-bridge", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-routing", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-bundle", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-core", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-csrf", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-guard", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-http", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-serializer", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-stopwatch", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-templating", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-translation", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bridge", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bundle", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-validator", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-var-dumper", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-link", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-profiler-bundle", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-server-bundle", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-workflow", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-symfony-yaml", ver:"3.4.22+dfsg-2+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);