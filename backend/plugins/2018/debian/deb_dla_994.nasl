###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_994.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 994-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.890994");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2017-5974", "CVE-2017-5975", "CVE-2017-5976", "CVE-2017-5978", "CVE-2017-5979", "CVE-2017-5980", "CVE-2017-5981");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 994-1] zziplib security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00023.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"zziplib on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
0.13.56-1.1+deb7u1.

We recommend that you upgrade your zziplib packages.");
  script_tag(name:"summary", value:"CVE-2017-5974
Heap-based buffer overflow in the __zzip_get32 function in fetch.c
in zziplib allows remote attackers to cause a denial of service
(crash) via a crafted ZIP file.

CVE-2017-5975
Heap-based buffer overflow in the __zzip_get64 function in fetch.c
in zziplib allows remote attackers to cause a denial of service
(crash) via a crafted ZIP file.

CVE-2017-5976
Heap-based buffer overflow in the zzip_mem_entry_extra_block
function in memdisk.c in zziplib allows remote attackers to cause
a denial of service (crash) via a crafted ZIP file.

CVE-2017-5978
The zzip_mem_entry_new function in memdisk.c in zziplib allows
remote attackers to cause a denial of service (out-of-bounds
read and crash) via a crafted ZIP file.

CVE-2017-5979
The prescan_entry function in fseeko.c in zziplib allows remote
attackers to cause a denial of service (NULL pointer dereference
and crash) via a crafted ZIP file.

CVE-2017-5980
The zzip_mem_entry_new function in memdisk.c in zziplib allows
remote attackers to cause a denial of service (NULL pointer
dereference and crash) via a crafted ZIP file.

CVE-2017-5981
seeko.c in zziplib allows remote attackers to cause a denial of
service (assertion failure and crash) via a crafted ZIP file.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libzzip-0-13", ver:"0.13.56-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libzzip-dev", ver:"0.13.56-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zziplib-bin", ver:"0.13.56-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}