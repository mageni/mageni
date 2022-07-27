###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1611.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1611-1 and DLA 1611-2 using nvtgen 1.0
# Script version: 2.0
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

# nb: This includes a manual merge of DLA 1611-1 and 1611-2

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891611");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2014-9317", "CVE-2015-6761", "CVE-2015-6818", "CVE-2015-6820", "CVE-2015-6821",
                "CVE-2015-6822", "CVE-2015-6823", "CVE-2015-6824", "CVE-2015-6825", "CVE-2015-6826",
                "CVE-2015-8216", "CVE-2015-8217", "CVE-2015-8363", "CVE-2015-8364", "CVE-2015-8661",
                "CVE-2015-8662", "CVE-2015-8663", "CVE-2016-10190", "CVE-2016-10191");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1611-1 and DLA 1611-2] libav security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-21 00:00:00 +0100 (Fri, 21 Dec 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00009.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00010.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"libav on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u3.

We recommend that you upgrade your libav packages.");
  script_tag(name:"summary", value:"DLA 1611-1:

Several security issues have been corrected in multiple demuxers and
decoders of the libav multimedia library.

CVE-2014-9317

    The decode_ihdr_chunk function in libavcodec/pngdec.c allowed remote
    attackers to cause a denial of service (out-of-bounds heap access)
    and possibly had other unspecified impact via an IDAT before an IHDR
    in a PNG file. The issue got addressed by checking IHDR/IDAT order.

CVE-2015-6761

    The update_dimensions function in libavcodec/vp8.c in libav relies on
    a coefficient-partition count during multi-threaded operation, which
    allowed remote attackers to cause a denial of service (race condition
    and memory corruption) or possibly have unspecified other impact via
    a crafted WebM file. This issue has been resolved by using
    num_coeff_partitions in thread/buffer setup. The variable is not a
    constant and can lead to race conditions.

CVE-2015-6818

    The decode_ihdr_chunk function in libavcodec/pngdec.c did not enforce
    uniqueness of the IHDR (aka image header) chunk in a PNG image, which
    allowed remote attackers to cause a denial of service (out-of-bounds
    array access) or possibly have unspecified other impact via a crafted
    image with two or more of these chunks. This has now been fixed by
    only allowing one IHDR chunk. Multiple IHDR chunks are forbidden in
    PNG.

Description truncated. Please see the references for more information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libav-dbg", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libav-doc", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libav-tools", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavcodec-extra", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavcodec-extra-56", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavcodec56", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavdevice55", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavfilter-dev", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavfilter5", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavformat-dev", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavformat56", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavresample-dev", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavresample2", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavutil-dev", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavutil54", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libswscale-dev", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libswscale3", ver:"6:11.12-1~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}