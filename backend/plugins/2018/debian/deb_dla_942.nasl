###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_942.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 942-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.890942");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-7885", "CVE-2017-7975", "CVE-2017-7976");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 942-1] jbig2dec security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-25 00:00:00 +0100 (Thu, 25 Jan 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00013.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"jbig2dec on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
0.13-4~deb7u2.

We recommend that you upgrade your jbig2dec packages.");
  script_tag(name:"summary", value:"CVE-2017-7885
Artifex jbig2dec 0.13 has a heap-based buffer over-read leading to
denial of service (application crash) or disclosure of sensitive
information from process memory, because of an integer overflow
in the jbig2_decode_symbol_dict function in jbig2_symbol_dict.c
in libjbig2dec.a during operation on a crafted .jb2 file.

CVE-2017-7975
Artifex jbig2dec 0.13, as used in Ghostscript, allows out-of-bounds
writes because of an integer overflow in the jbig2_build_huffman_table
function in jbig2_huffman.c during operations on a crafted JBIG2 file,
leading to a denial of service (application crash) or possibly
execution of arbitrary code.

CVE-2017-7976
Artifex jbig2dec 0.13 allows out-of-bounds writes and reads because
of an integer overflow in the jbig2_image_compose function in
jbig2_image.c during operations on a crafted .jb2 file, leading
to a denial of service (application crash) or disclosure of
sensitive information from process memory.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"jbig2dec", ver:"0.13-4~deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjbig2dec0", ver:"0.13-4~deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjbig2dec0-dev", ver:"0.13-4~deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}