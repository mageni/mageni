# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.892397");
  script_version("2020-10-07T03:00:10+0000");
  script_cve_id("CVE-2020-7070");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-10-07 09:36:44 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-07 03:00:10 +0000 (Wed, 07 Oct 2020)");
  script_name("Debian LTS: Security Advisory for php7.0 (DLA-2397-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2397-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.0'
  package(s) announced via the DLA-2397-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in PHP, a server-side, HTML-embedded
scripting language. When PHP is processing incoming HTTP cookie values,
the cookie names are url-decoded. This may lead to cookies with prefixes
like __Host confused with cookies that decode to such prefix, thus
leading to an attacker being able to forge a cookie which is supposed to
be secure.");

  script_tag(name:"affected", value:"'php7.0' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
7.0.33-0+deb9u10.

We recommend that you upgrade your php7.0 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.0", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libphp7.0-embed", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-bcmath", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-bz2", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-cgi", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-cli", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-common", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-curl", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-dba", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-dev", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-enchant", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-fpm", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-gd", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-gmp", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-imap", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-interbase", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-intl", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-json", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-ldap", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-mbstring", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-mcrypt", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-mysql", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-odbc", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-opcache", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-pgsql", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-phpdbg", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-pspell", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-readline", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-recode", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-snmp", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-soap", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-sqlite3", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-sybase", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-tidy", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-xml", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-xmlrpc", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-xsl", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php7.0-zip", ver:"7.0.33-0+deb9u10", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
