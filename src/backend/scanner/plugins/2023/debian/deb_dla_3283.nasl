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
  script_oid("1.3.6.1.4.1.25623.1.0.893283");
  script_version("2023-01-27T10:09:24+0000");
  script_cve_id("CVE-2022-39956", "CVE-2022-48279", "CVE-2023-24021");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-27 02:00:08 +0000 (Fri, 27 Jan 2023)");
  script_name("Debian LTS: Security Advisory for modsecurity-apache (DLA-3283-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00023.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3283-1");
  script_xref(name:"Advisory-ID", value:"DLA-3283-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1029329");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'modsecurity-apache'
  package(s) announced via the DLA-3283-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in modsecurity-apache, open source, cross
platform web application firewall (WAF) engine for Apache which allows
remote attackers to bypass the applications firewall and other
unspecified impact.

CVE-2022-48279

In ModSecurity before 2.9.6 and 3.x before 3.0.8, HTTP multipart
requests were incorrectly parsed and could bypass the Web Application
Firewall.
NOTE: this is related to CVE-2022-39956 but can be considered
independent changes to the ModSecurity(C language) codebase.

CVE-2023-24021

Incorrect handling of null-bytes in file uploads in ModSecurity
before 2.9.7 may allow for Web Application Firewall bypasses and
buffer iverflows on the Web Application Firewall when executing
rules reading the FILES_TMP_CONTENT collection.");

  script_tag(name:"affected", value:"'modsecurity-apache' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2.9.3-1+deb10u2.

We recommend that you upgrade your modsecurity-apache packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-security2", ver:"2.9.3-1+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
