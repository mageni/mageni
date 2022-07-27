###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1630.nasl 14274 2019-03-18 14:38:37Z cfischer $
#
# Auto-generated from advisory DLA 1630-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.891630");
  script_version("$Revision: 14274 $");
  script_cve_id("CVE-2017-14055", "CVE-2017-14056", "CVE-2017-14057", "CVE-2017-14170", "CVE-2017-14171",
                "CVE-2017-14767", "CVE-2017-15672", "CVE-2017-17130", "CVE-2017-9993", "CVE-2017-9994",
                "CVE-2018-14394", "CVE-2018-1999010", "CVE-2018-6621", "CVE-2018-7557");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1630-1] libav security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:38:37 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-01-08 00:00:00 +0100 (Tue, 08 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00006.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"libav on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u4.

We recommend that you upgrade your libav packages.");
  script_tag(name:"summary", value:"Several security vulnerabilities were corrected in the libav
multimedia library which may lead to a denial-of-service, information
disclosure or the execution of arbitrary code if a malformed file is
processed.

CVE-2017-9993

Libav does not properly restrict HTTP Live Streaming filename
extensions and demuxer names, which allows attackers to read
arbitrary files via crafted playlist data.

CVE-2017-9994

libavcodec/webp.c in Libav does not ensure that pix_fmt is set,
which allows remote attackers to cause a denial of service
(heap-based buffer overflow and application crash) or possibly have
unspecified other impact via a crafted file, related to the
vp8_decode_mb_row_no_filter and pred8x8_128_dc_8_c functions.

CVE-2017-14055

Denial-of-service in mv_read_header() due to lack of an EOF (End of
File) check might cause huge CPU and memory consumption.

CVE-2017-14056

Denial-of-service in rl2_read_header() due to lack of an EOF
(End of File) check might cause huge CPU and memory consumption.

CVE-2017-14057

Denial-of-service in asf_read_marker() due to lack of an EOF
(End of File) check might cause huge CPU and memory consumption.

CVE-2017-14170

Denial-of-service in mxf_read_index_entry_array() due to lack of an
EOF (End of File) check might cause huge CPU consumption.

CVE-2017-14171

Denial-of-service in nsv_parse_NSVf_header() due to lack of an EOF
(End of File) check might cause huge CPU consumption.

CVE-2017-14767

The sdp_parse_fmtp_config_h264 function in
libavformat/rtpdec_h264.c mishandles empty sprop-parameter-sets
values, which allows remote attackers to cause a denial of service
(heap buffer overflow) or possibly have unspecified other impact via
a crafted sdp file.

CVE-2017-15672

The read_header function in libavcodec/ffv1dec.c allows remote
attackers to have unspecified impact via a crafted MP4 file, which
triggers an out-of-bounds read.

CVE-2017-17130

The ff_free_picture_tables function in libavcodec/mpegpicture.c
allows remote attackers to cause a denial of service
(heap-based buffer overflow and application crash) or possibly have
unspecified other impact via a crafted file, related to
vc1_decode_i_blocks_adv.

CVE-2018-6621

The decode_frame function in libavcodec/utvideodec.c in Libav allows
remote attackers to cause a denial of service (out of array read)
via a crafted AVI file.

CVE-2018-7557

The decode_init function in libavcodec/utvideodec.c in
Libav allows remote attackers to cause a denial of service
(Out of array read) via an AVI file with crafted dimensions within
chroma subsampling data.

CVE-2018-14394

libavformat/movenc.c in Libav allows attackers to cause a
denial of service (application crash caused by a divide-by-zero
error) with a user crafted Waveform audio file.

CVE-2018-1999010

Libav contains multiple out of array access vulnerabilities in the
mms protocol that can result in attackers accessing out of bound
data.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libav-dbg", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libav-doc", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libav-tools", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavcodec-extra", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavcodec-extra-56", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavcodec56", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavdevice55", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavfilter-dev", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavfilter5", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavformat-dev", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavformat56", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavresample-dev", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavresample2", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavutil-dev", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libavutil54", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libswscale-dev", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libswscale3", ver:"6:11.12-1~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}