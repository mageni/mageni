###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1595.nasl 14275 2019-03-18 14:39:45Z cfischer $
#
# Auto-generated from advisory DLA 1595-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891595");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2018-19490", "CVE-2018-19491", "CVE-2018-19492");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1595-1] gnuplot5 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-11-26 00:00:00 +0100 (Mon, 26 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00031.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"gnuplot5 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
5.0.0~rc+dfsg2-1+deb8u1.

We recommend that you upgrade your gnuplot5 packages.");
  script_tag(name:"summary", value:"gnuplot5, a command-line driven interactive plotting program, has been
examined with fuzzing by Tim Blazytko, Cornelius Aschermann, Sergej
Schumilo and Nils Bars.
They found various overflow cases which might lead to the execution of
arbitrary code.

  Due to special toolchain hardening in Debian, CVE-2018-19492 is not security relevant, but it is a bug and
  the patch was applied for the sake of completeness. Probably some downstream project does not have the same toolchain settings.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gnuplot5", ver:"5.0.0~rc+dfsg2-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnuplot5-data", ver:"5.0.0~rc+dfsg2-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnuplot5-doc", ver:"5.0.0~rc+dfsg2-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnuplot5-nox", ver:"5.0.0~rc+dfsg2-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnuplot5-qt", ver:"5.0.0~rc+dfsg2-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnuplot5-x11", ver:"5.0.0~rc+dfsg2-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}