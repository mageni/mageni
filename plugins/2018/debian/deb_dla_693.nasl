###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_693.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 693-2 using nvtgen 1.0
# Script version:2.0
# #
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
  script_oid("1.3.6.1.4.1.25623.1.0.890693");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2014-8128", "CVE-2015-7554", "CVE-2015-8668", "CVE-2016-3186",
                "CVE-2016-3619", "CVE-2016-3620", "CVE-2016-3621", "CVE-2016-3631",
		"CVE-2016-3632", "CVE-2016-3633", "CVE-2016-3634", "CVE-2016-5102",
		"CVE-2016-5318", "CVE-2016-5319", "CVE-2016-5652", "CVE-2016-6223",
		"CVE-2016-8331");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 693-2] tiff regression update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-05 00:00:00 +0100 (Fri, 05 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00005.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"tiff on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
4.0.2-6+deb7u10.

We recommend that you upgrade your tiff packages.");
  script_tag(name:"summary", value:"Version 4.0.2-6+deb7u7 introduced changes that resulted in libtiff
being unable to write out tiff files when the compression scheme
in use relies on codec-specific TIFF tags embedded in the image.

This problem manifested itself with errors like those:
$ tiffcp -r 16 -c jpeg sample.tif out.tif
_TIFFVGetField: out.tif: Invalid tag 'Predictor' (not supported by codec).
_TIFFVGetField: out.tif: Invalid tag 'BadFaxLines' (not supported by codec).
tiffcp: tif_dirwrite.c:687: TIFFWriteDirectorySec: Assertion `0' failed.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.2-6+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.2-6+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.2-6+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.2-6+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5-alt-dev", ver:"4.0.2-6+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.0.2-6+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.2-6+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}