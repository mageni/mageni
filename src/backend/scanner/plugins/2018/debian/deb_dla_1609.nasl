###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1609.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1609-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891609");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-11759");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1609-1] libapache-mod-jk security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-18 00:00:00 +0100 (Tue, 18 Dec 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00007.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/connectors-doc/miscellaneous/changelog.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"libapache-mod-jk on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
1.2.46-0+deb8u1.

We recommend that you upgrade your libapache-mod-jk packages.");
  script_tag(name:"summary", value:"A vulnerability has been discovered in libapache-mod-jk, the Apache 2
connector for the Tomcat Java servlet engine.

The libapache-mod-jk connector is susceptible to information disclosure
and privilege escalation because of a mishandling of URL normalization.

The nature of the fix required that libapache-mod-jk in Debian 8
'Jessie' be updated to the latest upstream release.  For reference, the
upstream changes associated with each release version are documented
in the linked references.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache-mod-jk-doc", ver:"1.2.46-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-jk", ver:"1.2.46-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}