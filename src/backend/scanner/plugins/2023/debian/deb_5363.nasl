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
  script_oid("1.3.6.1.4.1.25623.1.0.705363");
  script_cve_id("CVE-2022-31631", "CVE-2023-0567", "CVE-2023-0568", "CVE-2023-0662");
  script_tag(name:"creation_date", value:"2023-02-28 02:00:11 +0000 (Tue, 28 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 18:02:00 +0000 (Fri, 03 Mar 2023)");

  script_name("Debian: Security Advisory (DSA-5363)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5363");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5363");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php7.4");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php7.4' package(s) announced via the DSA-5363 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were found in PHP, a widely-used open source general purpose scripting language which could result in denial of service or incorrect validation of BCrypt hashes.

For the stable distribution (bullseye), these problems have been fixed in version 7.4.33-1+deb11u3.

We recommend that you upgrade your php7.4 packages.

For the detailed security status of php7.4 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'php7.4' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.4", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libphp7.4-embed", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-bcmath", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-bz2", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cgi", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cli", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-common", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-curl", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-dba", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-dev", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-enchant", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-fpm", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-gd", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-gmp", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-imap", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-interbase", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-intl", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-json", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-ldap", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-mbstring", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-mysql", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-odbc", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-opcache", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-pgsql", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-phpdbg", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-pspell", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-readline", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-snmp", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-soap", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-sqlite3", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-sybase", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-tidy", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-xml", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-xmlrpc", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-xsl", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-zip", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4", ver:"7.4.33-1+deb11u3", rls:"DEB11"))) {
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
