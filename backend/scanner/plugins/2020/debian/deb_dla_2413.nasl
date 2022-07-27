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
  script_oid("1.3.6.1.4.1.25623.1.0.892413");
  script_version("2020-10-26T04:00:22+0000");
  script_cve_id("CVE-2019-19617", "CVE-2020-26934", "CVE-2020-26935");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-26 11:10:40 +0000 (Mon, 26 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-26 04:00:22 +0000 (Mon, 26 Oct 2020)");
  script_name("Debian LTS: Security Advisory for phpmyadmin (DLA-2413-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00024.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2413-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/971999");
  script_xref(name:"URL", value:"https://bugs.debian.org/972000");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin'
  package(s) announced via the DLA-2413-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in package phpmyadmin.

CVE-2019-19617

phpMyAdmin does not escape certain Git information, related to
libraries/classes/Display/GitRevision.php and libraries/classes
/Footer.php.

CVE-2020-26934

A vulnerability was discovered where an attacker can cause an XSS
attack through the transformation feature.

If an attacker sends a crafted link to the victim with the malicious
JavaScript, when the victim clicks on the link, the JavaScript will run
and complete the instructions made by the attacker.

CVE-2020-26935

An SQL injection vulnerability was discovered in how phpMyAdmin
processes SQL statements in the search feature. An attacker could use
this flaw to inject malicious SQL in to a query.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.6.6-4+deb9u2.

We recommend that you upgrade your phpmyadmin packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4.6.6-4+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
