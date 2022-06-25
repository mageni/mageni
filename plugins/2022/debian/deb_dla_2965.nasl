# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892965");
  script_version("2022-03-30T01:00:11+0000");
  script_cve_id("CVE-2018-10060", "CVE-2018-10061", "CVE-2019-11025", "CVE-2020-13230", "CVE-2020-23226", "CVE-2020-7106", "CVE-2021-23225", "CVE-2022-0730");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-30 10:16:33 +0000 (Wed, 30 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-30 01:00:11 +0000 (Wed, 30 Mar 2022)");
  script_name("Debian LTS: Security Advisory for cacti (DLA-2965-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/03/msg00038.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2965-1");
  script_xref(name:"Advisory-ID", value:"DLA-2965-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/926700");
  script_xref(name:"URL", value:"https://bugs.debian.org/949996");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti'
  package(s) announced via the DLA-2965-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Cacti, a web interface for
graphing of monitoring systems, leading to authentication bypass and
cross-site scripting (XSS). An attacker may get access to unauthorized
areas and impersonate other users, under certain conditions.

CVE-2018-10060

Cacti has XSS because it does not properly reject unintended
characters, related to use of the sanitize_uri function in
lib/functions.php.

CVE-2018-10061

Cacti has XSS because it makes certain htmlspecialchars calls
without the ENT_QUOTES flag (these calls occur when the
html_escape function in lib/html.php is not used).

CVE-2019-11025

No escaping occurs before printing out the value of the SNMP
community string (SNMP Options) in the View poller cache, leading
to XSS.

CVE-2020-7106

Cacti has stored XSS in multiple files as demonstrated by the
description parameter in data_sources.php (a raw string from the
database that is displayed by $header to trigger the XSS).

CVE-2020-13230

Disabling a user account does not immediately invalidate any
permissions granted to that account (e.g., permission to view
logs).

CVE-2020-23226

Multiple Cross Site Scripting (XSS) vulnerabilities exist in
multiple files.

CVE-2021-23225

Cacti allows authenticated users with User Management permissions
to inject arbitrary web script or HTML in the 'new_username' field
during creation of a new user via 'Copy' method at user_admin.php.

CVE-2022-0730

Under certain ldap conditions, Cacti authentication can be
bypassed with certain credential types.");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0.8.8h+ds1-10+deb9u2.

We recommend that you upgrade your cacti packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.8h+ds1-10+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
