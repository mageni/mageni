###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1658.nasl 14282 2019-03-18 14:55:18Z cfischer $
#
# Auto-generated from advisory DLA 1658-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891658");
  script_version("$Revision: 14282 $");
  script_cve_id("CVE-2018-19968", "CVE-2018-19970");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1658-1] phpmyadmin security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:55:18 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-04 00:00:00 +0100 (Mon, 04 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00003.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"phpmyadmin on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4:4.2.12-2+deb8u4.

We recommend that you upgrade your phpmyadmin packages.");
  script_tag(name:"summary", value:"A couple of vulnerabilities have been discovered in phpmyadmin, MySQL web
administration tool.

CVE-2018-19968

An attacker can exploit phpMyAdmin before 4.8.4 to leak the contents of a
local file because of an error in the transformation feature. The attacker
must have access to the phpMyAdmin Configuration Storage tables, although
these can easily be created in any database to which the attacker has
access. An attacker must have valid credentials to log in to phpMyAdmin.
This vulnerability does not allow an attacker to circumvent the login
system.

CVE-2018-19970

A XSS vulnerability was found in the navigation tree, where an attacker can
deliver a payload to a user through a crafted database/table name.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.2.12-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}