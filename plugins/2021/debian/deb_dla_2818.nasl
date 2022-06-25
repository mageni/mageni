# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892818");
  script_version("2021-11-18T02:00:20+0000");
  script_cve_id("CVE-2020-20445", "CVE-2020-20446", "CVE-2020-20451", "CVE-2020-20453", "CVE-2020-22037", "CVE-2020-22041", "CVE-2020-22044", "CVE-2020-22046", "CVE-2020-22048", "CVE-2020-22049", "CVE-2020-22054", "CVE-2021-38171", "CVE-2021-38291");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-18 02:00:20 +0000 (Thu, 18 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-18 02:00:20 +0000 (Thu, 18 Nov 2021)");
  script_name("Debian LTS: Security Advisory for ffmpeg (DLA-2818-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/11/msg00012.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2818-1");
  script_xref(name:"Advisory-ID", value:"DLA-2818-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the DLA-2818-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been discovered in ffmpeg - tools for transcoding,
streaming and playing of multimedia files.

CVE-2020-20445

Divide By Zero issue via libavcodec/lpc.h, which allows a remote malicious
user to cause a Denial of Service.

CVE-2020-20446

Divide By Zero issue via libavcodec/aacpsy.c, which allows a remote malicious
user to cause a Denial of Service.

CVE-2020-20451

Denial of Service issue due to resource management errors via
fftools/cmdutils.c.

CVE-2020-20453

Divide By Zero issue via libavcodec/aaccoder, which allows a remote
malicious user to cause a Denial of Service.

CVE-2020-22037

A Denial of Service vulnerability due to a memory leak in
avcodec_alloc_context3 at options.c

CVE-2020-22041

A Denial of Service vulnerability due to a memory leak in
the av_buffersrc_add_frame_flags function in buffersrc.

CVE-2020-22044

A Denial of Service vulnerability due to a memory leak in the
url_open_dyn_buf_internal function in libavformat/aviobuf.c.

CVE-2020-22046

A Denial of Service vulnerability due to a memory leak in the
avpriv_float_dsp_allocl function in libavutil/float_dsp.c.

CVE-2020-22048

A Denial of Service vulnerability due to a memory leak in the
ff_frame_pool_get function in framepool.c.

CVE-2020-22049

A Denial of Service vulnerability due to a memory leak in the
wtvfile_open_sector function in wtvdec.c.

CVE-2020-22054

A Denial of Service vulnerability due to a memory leak in the av_dict_set
function in dict.c.

CVE-2021-38171

adts_decode_extradata in libavformat/adtsenc.c does not check the
init_get_bits return value, which is a necessary step because the second
argument to init_get_bits can be crafted.

CVE-2021-38291

Assertion failure at src/libavutil/mathematics.c, causing ffmpeg aborted
is detected. In some extrme cases, like with adpcm_ms samples with an
extremely high channel count, get_audio_frame_duration() may return a
negative frame duration value.");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
7:3.2.16-1+deb9u1.

We recommend that you upgrade your ffmpeg packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libav-tools", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-dev", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra57", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec57", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavdevice-dev", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavdevice57", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter-dev", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra6", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter6", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavformat-dev", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavformat57", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavresample-dev", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavresample3", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavutil-dev", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavutil55", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpostproc-dev", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpostproc54", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswresample-dev", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswresample2", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswscale4", ver:"7:3.2.16-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
