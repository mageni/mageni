###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_880.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 880-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.890880");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2015-8784", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 880-1] tiff3 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00039.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"tiff3 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
3.9.6-11+deb7u4.

We recommend that you upgrade your tiff3 packages.");
  script_tag(name:"summary", value:"tiff3 is affected by multiple issues that can result at least in denial of
services of applications using libtiff4. Crafted TIFF files can be
provided to trigger: abort() calls via failing assertions, buffer overruns
(both in read and write mode).

CVE-2015-8781

tif_luv.c in libtiff allows attackers to cause a denial of service
(out-of-bounds write) via an invalid number of samples per pixel in a
LogL compressed TIFF image.

CVE-2015-8782

tif_luv.c in libtiff allows attackers to cause a denial of service
(out-of-bounds writes) via a crafted TIFF image.

CVE-2015-8783

tif_luv.c in libtiff allows attackers to cause a denial of service
(out-of-bounds reads) via a crafted TIFF image.

CVE-2015-8784

The NeXTDecode function in tif_next.c in LibTIFF allows remote
attackers to cause a denial of service (out-of-bounds write) via a
crafted TIFF image.

CVE-2016-9533

tif_pixarlog.c in libtiff 4.0.6 has out-of-bounds write
vulnerabilities in heap allocated buffers.

CVE-2016-9534

tif_write.c in libtiff 4.0.6 has an issue in the error code path of
TIFFFlushData1() that didn't reset the tif_rawcc and tif_rawcp
members.

CVE-2016-9535

tif_predict.h and tif_predict.c in libtiff 4.0.6 have assertions
that can lead to assertion failures in debug mode, or buffer
overflows in release mode, when dealing with unusual tile size
like YCbCr with subsampling.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.6-11+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.9.6-11+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.9.6-11+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}