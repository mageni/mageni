###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1583.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1583-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891583");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2015-5203", "CVE-2015-5221", "CVE-2016-8690", "CVE-2016-8884", "CVE-2016-8885",
                "CVE-2017-13748", "CVE-2017-14132");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1583-1] jasper security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-11-21 00:00:00 +0100 (Wed, 21 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00023.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"jasper on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.900.1-debian1-2.4+deb8u4.

We recommend that you upgrade your jasper packages.");
  script_tag(name:"summary", value:"Several security vulnerabilities were discovered in the JasPer
JPEG-2000 library.

CVE-2015-5203

Gustavo Grieco discovered an integer overflow vulnerability that
allows remote attackers to cause a denial of service or may have
other unspecified impact via a crafted JPEG 2000 image file.

CVE-2015-5221

Josselin Feist found a double-free vulnerability that allows remote
attackers to cause a denial-of-service (application crash) by
processing a malformed image file.

CVE-2016-8690

Gustavo Grieco discovered a NULL pointer dereference vulnerability
that can cause a denial-of-service via a crafted BMP image file. The
update also includes the fixes for the related issues CVE-2016-8884
and CVE-2016-8885 which complete the patch for CVE-2016-8690.

CVE-2017-13748

It was discovered that jasper does not properly release memory used
to store image tile data when image decoding fails which may lead to
a denial-of-service.

CVE-2017-14132

A heap-based buffer over-read was found related to the
jas_image_ishomosamp function that could be triggered via a crafted
image file and may cause a denial-of-service (application crash) or
have other unspecified impact.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-debian1-2.4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-debian1-2.4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjasper1", ver:"1.900.1-debian1-2.4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}