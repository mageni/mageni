# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891740");
  script_version("2019-04-03T11:45:59+0000");
  script_cve_id("CVE-2015-1872", "CVE-2017-1000460", "CVE-2017-14058", "CVE-2018-1999012", "CVE-2018-6392");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-04-03 11:45:59 +0000 (Wed, 03 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1740-1] libav security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00041.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1740-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libav'
  package(s) announced via the DSA-1740-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been corrected in multiple demuxers and
decoders of the libav multimedia library.

CVE-2015-1872

The ff_mjpeg_decode_sof function in libavcodec/mjpegdec.c did not
validate the number of components in a JPEG-LS Start Of Frame
segment, which allowed remote attackers to cause a denial of service
(out-of-bounds array access) or possibly have unspecified other
impact via crafted Motion JPEG data.

CVE-2017-14058

The read_data function in libavformat/hls.c did not restrict reload
attempts for an insufficient list, which allowed remote attackers to
cause a denial of service (infinite loop).

CVE-2017-1000460

In get_last_needed_nal() (libavformat/h264.c) the return value of
init_get_bits was ignored and get_ue_golomb(&gb) was called on an
uninitialized get_bits context, which caused a NULL deref exception.

CVE-2018-6392

The filter_slice function in libavfilter/vf_transpose.c allowed
remote attackers to cause a denial of service (out-of-array access)
via a crafted MP4 file.

CVE-2018-1999012

libav contained a CWE-835: Infinite loop vulnerability in pva format
demuxer that could result in a vulnerability that allowed attackers to
consume excessive amount of resources like CPU and RAM. This attack
appeared to be exploitable via specially crafted PVA file had to be
provided as input.");

  script_tag(name:"affected", value:"'libav' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u6.

We recommend that you upgrade your libav packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libav-dbg", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libav-doc", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libav-tools", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-dev", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra-56", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec56", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavdevice-dev", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavdevice55", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter-dev", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter5", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavformat-dev", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavformat56", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavresample-dev", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavresample2", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavutil-dev", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavutil54", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswscale3", ver:"6:11.12-1~deb8u6", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);