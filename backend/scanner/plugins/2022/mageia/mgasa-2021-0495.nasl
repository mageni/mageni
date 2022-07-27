# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0495");
  script_cve_id("CVE-2020-20446", "CVE-2020-20450", "CVE-2020-20453", "CVE-2020-21041", "CVE-2020-22015", "CVE-2020-22019", "CVE-2020-22021", "CVE-2020-22033", "CVE-2020-22037", "CVE-2020-22038", "CVE-2020-22042", "CVE-2021-38114", "CVE-2021-38171", "CVE-2021-38291");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-30 15:37:00 +0000 (Mon, 30 Aug 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0495)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0495");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0495.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29256");
  script_xref(name:"URL", value:"http://ffmpeg.org/security.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-July/009140.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MM55YS6XXAKFK3J35CDODMYMAZO6JX3S/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RHYNSW2TAJSSTZPOYXQXGZDI6LYBWIT4/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UQYGWX5BP3LA5ULPF6C7O7URBPXWRNFJ/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4990");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg, ffmpeg' package(s) announced via the MGASA-2021-0495 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/aacpsy.c,
which allows a remote malicious user to cause a Denial of Service.
(CVE-2020-20446)

FFmpeg 4.2 is affected by null pointer dereference passed as argument to
libavformat/aviobuf.c, which could cause a Denial of Service.
(CVE-2020-20450)

FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/aaccoder,
which allows a remote malicious user to cause a Denial of Service.
(CVE-2020-20453)

Buffer Overflow vulnerability exists in FFmpeg 4.1 via apng_do_inverse_blend
in libavcodec/pngenc.c, which could let a remote malicious user cause a
Denial of Service. (CVE-2020-21041)

Buffer Overflow vulnerability in FFmpeg 4.2 in mov_write_video_tag due to
the out of bounds in libavformat/movenc.c, which could let a remote
malicious user obtain sensitive information, cause a Denial of Service, or
execute arbitrary code. (CVE-2020-22015)

Buffer Overflow vulnerability in FFmpeg 4.2 at convolution_y_10bit in
libavfilter/vf_vmafmotion.c, which could let a remote malicious user cause
a Denial of Service. (CVE-2020-22019)

Buffer Overflow vulnerability in FFmpeg 4.2 at filter_edges function in
libavfilter/vf_yadif.c, which could let a remote malicious user cause a
Denial of Service. (CVE-2020-22021)

A heap-based Buffer Overflow Vulnerability exists FFmpeg 4.2 at
libavfilter/vf_vmafmotion.c in convolution_y_8bit, which could let a remote
malicious user cause a Denial of Service. (CVE-2020-22033)

A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak
in avcodec_alloc_context3 at options.c. (CVE-2020-22037)

A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak
in the ff_v4l2_m2m_create_context function in v4l2_m2m.c. (CVE-2020-22038)

A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak
is affected by: memory leak in the link_filter_inouts function in
libavfilter/graphparser.c. (CVE-2020-22042)

libavcodec/dnxhddec.c in FFmpeg 4.4 does not check the return value of the
init_vlc function, a similar issue to CVE-2013-0868. (CVE-2021-38114)

adts_decode_extradata in libavformat/adtsenc.c in FFmpeg 4.4 does not check
the init_get_bits return value, which is a necessary step because the second
argument to init_get_bits can be crafted. (CVE-2021-38171)

FFmpeg version (git commit de8e6e67e7523e48bb27ac224a0b446df05e1640) suffers
from a an assertion failure at src/libavutil/mathematics.c. (CVE-2021-38291)");

  script_tag(name:"affected", value:"'ffmpeg, ffmpeg' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec58", rpm:"lib64avcodec58~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec58", rpm:"lib64avcodec58~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter7", rpm:"lib64avfilter7~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter7", rpm:"lib64avfilter7~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat58", rpm:"lib64avformat58~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat58", rpm:"lib64avformat58~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avresample4", rpm:"lib64avresample4~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avresample4", rpm:"lib64avresample4~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil56", rpm:"lib64avutil56~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil56", rpm:"lib64avutil56~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc55", rpm:"lib64postproc55~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc55", rpm:"lib64postproc55~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample3", rpm:"lib64swresample3~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample3", rpm:"lib64swresample3~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler5", rpm:"lib64swscaler5~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler5", rpm:"lib64swscaler5~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58", rpm:"libavcodec58~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58", rpm:"libavcodec58~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7", rpm:"libavfilter7~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7", rpm:"libavfilter7~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58", rpm:"libavformat58~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58", rpm:"libavformat58~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4", rpm:"libavresample4~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4", rpm:"libavresample4~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56", rpm:"libavutil56~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56", rpm:"libavutil56~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55", rpm:"libpostproc55~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55", rpm:"libpostproc55~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3", rpm:"libswresample3~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3", rpm:"libswresample3~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler5", rpm:"libswscaler5~4.3.3~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler5", rpm:"libswscaler5~4.3.3~3.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
