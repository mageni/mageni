###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1297.nasl 14284 2019-03-18 15:02:15Z cfischer $
#
# Auto-generated from advisory DLA 1297-1 using nvtgen 1.0
# Script version: 1.9
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
  script_oid("1.3.6.1.4.1.25623.1.0.891297");
  script_version("$Revision: 14284 $");
  script_cve_id("CVE-2018-7435", "CVE-2018-7436", "CVE-2018-7437",
                "CVE-2018-7438", "CVE-2018-7439");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1297-1] freexl security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 16:02:15 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00000.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"freexl on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.0.0b-1+deb7u5.

We recommend that you upgrade your freexl packages.");
  script_tag(name:"summary", value:"Leon reported five heap-based buffer-overflow vulnerabilities in FreeXL.

CVE-2018-7435

    There is a heap-based buffer over-read in the freexl::destroy_cell
    function.

CVE-2018-7436

    There is a heap-based buffer over-read in a pointer dereference of
    the parse_SST function.

CVE-2018-7437

    There is a heap-based buffer over-read in a memcpy call of the
    parse_SST function.

CVE-2018-7438

    There is a heap-based buffer over-read in the parse_unicode_string
    function.

CVE-2018-7439

    There is a heap-based buffer over-read in the function
    read_mini_biff_next_record.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libfreexl-dev", ver:"1.0.0b-1+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreexl1", ver:"1.0.0b-1+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreexl1-dbg", ver:"1.0.0b-1+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}