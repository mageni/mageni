# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893345");
  script_cve_id("CVE-2022-31631", "CVE-2023-0567", "CVE-2023-0568", "CVE-2023-0662");
  script_tag(name:"creation_date", value:"2023-02-27 02:00:07 +0000 (Mon, 27 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 18:02:00 +0000 (Fri, 03 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-3345)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3345");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3345");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php7.3");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php7.3' package(s) announced via the DLA-3345 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were found in PHP, a widely-used open source general purpose scripting language, which could result in denial of service or incorrect validation of BCrypt hashes.

CVE-2022-31631

Due to an uncaught integer overflow, PDO::quote() of PDO_SQLite may return an improperly quoted string. The exact details likely depend on the implementation of sqlite3_snprintf(), but with some versions it is possible to force the function to return a single apostrophe, if the function is called on user supplied input without any length restrictions in place.

CVE-2023-0567

Tim Dusterhus discovered that malformed BCrypt hashes that include a $ character within their salt part trigger a buffer overread and may erroneously validate any password as valid. (Password_verify() always returns true with such inputs.)

CVE-2023-0568

1-byte array overrun when appending slash to paths during path resolution.

CVE-2023-0662

Jakob Ackermann discovered a Denial of Service vulnerability when parsing multipart request body: the request body parsing in PHP allows any unauthenticated attacker to consume a large amount of CPU time and trigger excessive logging.

For Debian 10 buster, these problems have been fixed in version 7.3.31-1~deb10u3.

We recommend that you upgrade your php7.3 packages.

For the detailed security status of php7.3 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'php7.3' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.3", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libphp7.3-embed", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-bcmath", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-bz2", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-cgi", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-cli", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-common", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-curl", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-dba", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-dev", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-enchant", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-fpm", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-gd", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-gmp", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-imap", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-interbase", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-intl", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-json", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-ldap", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-mbstring", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-mysql", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-odbc", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-opcache", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-pgsql", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-phpdbg", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-pspell", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-readline", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-recode", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-snmp", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-soap", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-sqlite3", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-sybase", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-tidy", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-xml", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-xmlrpc", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-xsl", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3-zip", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.3", ver:"7.3.31-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
