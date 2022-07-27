###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1496.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1496-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891496");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-16435");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1496-1] lcms2 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-06 00:00:00 +0200 (Thu, 06 Sep 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00005.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"lcms2 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this issue has been fixed in lcms2 version
2.6-3+deb8u2.

We recommend that you upgrade your lcms2 packages.");
  script_tag(name:"summary", value:"It was discovered that there was an integer overflow vulnerability
in the 'Little CMS 2' colour management library. A specially-crafted
input file could lead to a heap-based buffer overflow.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"liblcms2-2", ver:"2.6-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"liblcms2-dbg", ver:"2.6-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"liblcms2-dev", ver:"2.6-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"liblcms2-utils", ver:"2.6-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}