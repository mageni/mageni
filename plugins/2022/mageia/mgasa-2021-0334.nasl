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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0334");
  script_cve_id("CVE-2021-3522");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-09 16:21:00 +0000 (Wed, 09 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0334)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0334");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0334.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28977");
  script_xref(name:"URL", value:"https://gitlab.freedesktop.org/gstreamer/gst-plugins-bad/-/merge_requests/2103");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4903");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4902");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4959-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer1.0-plugins-bad, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-base, gstreamer1.0-plugins-base' package(s) announced via the MGASA-2021-0334 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GStreamer before 1.18.4 may perform an out-of-bounds read when handling certain
ID3v2 tags (CVE-2021-3522).

Overflows in AVC/HEVC NAL unit length calculations, which would lead to
allocating infinite amounts of small memory blocks until OOM and could
potentially also lead to memory corruptions.");

  script_tag(name:"affected", value:"'gstreamer1.0-plugins-bad, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-base, gstreamer1.0-plugins-base' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdparanoia", rpm:"gstreamer1.0-cdparanoia~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-curl", rpm:"gstreamer1.0-curl~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-curl", rpm:"gstreamer1.0-curl~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dash", rpm:"gstreamer1.0-dash~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dash", rpm:"gstreamer1.0-dash~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-faad", rpm:"gstreamer1.0-faad~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fdkaac", rpm:"gstreamer1.0-fdkaac~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fluidsynth", rpm:"gstreamer1.0-fluidsynth~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fluidsynth", rpm:"gstreamer1.0-fluidsynth~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gme", rpm:"gstreamer1.0-gme~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gme", rpm:"gstreamer1.0-gme~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gsm", rpm:"gstreamer1.0-gsm~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gsm", rpm:"gstreamer1.0-gsm~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ladspa", rpm:"gstreamer1.0-ladspa~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ladspa", rpm:"gstreamer1.0-ladspa~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libass", rpm:"gstreamer1.0-libass~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libass", rpm:"gstreamer1.0-libass~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libvisual", rpm:"gstreamer1.0-libvisual~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mms", rpm:"gstreamer1.0-mms~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mms", rpm:"gstreamer1.0-mms~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg2enc", rpm:"gstreamer1.0-mpeg2enc~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg2enc", rpm:"gstreamer1.0-mpeg2enc~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-neon", rpm:"gstreamer1.0-neon~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-neon", rpm:"gstreamer1.0-neon~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ofa", rpm:"gstreamer1.0-ofa~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ofa", rpm:"gstreamer1.0-ofa~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad", rpm:"gstreamer1.0-plugins-bad~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad", rpm:"gstreamer1.0-plugins-bad~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad-doc", rpm:"gstreamer1.0-plugins-bad-doc~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad-doc", rpm:"gstreamer1.0-plugins-bad-doc~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-base", rpm:"gstreamer1.0-plugins-base~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtmp", rpm:"gstreamer1.0-rtmp~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtmp", rpm:"gstreamer1.0-rtmp~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sbc", rpm:"gstreamer1.0-sbc~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sbc", rpm:"gstreamer1.0-sbc~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-smoothstreaming", rpm:"gstreamer1.0-smoothstreaming~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-smoothstreaming", rpm:"gstreamer1.0-smoothstreaming~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soundtouch", rpm:"gstreamer1.0-soundtouch~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soundtouch", rpm:"gstreamer1.0-soundtouch~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-spandsp", rpm:"gstreamer1.0-spandsp~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-spandsp", rpm:"gstreamer1.0-spandsp~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-srtp", rpm:"gstreamer1.0-srtp~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-srtp", rpm:"gstreamer1.0-srtp~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wildmidi", rpm:"gstreamer1.0-wildmidi~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wildmidi", rpm:"gstreamer1.0-wildmidi~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-x265", rpm:"gstreamer1.0-x265~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio1.0_0", rpm:"lib64gstbadaudio1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio1.0_0", rpm:"lib64gstbadaudio1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasecamerabinsrc1.0_0", rpm:"lib64gstbasecamerabinsrc1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasecamerabinsrc1.0_0", rpm:"lib64gstbasecamerabinsrc1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecparsers1.0_0", rpm:"lib64gstcodecparsers1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecparsers1.0_0", rpm:"lib64gstcodecparsers1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl-gir1.0", rpm:"lib64gstgl-gir1.0~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl1.0_0", rpm:"lib64gstgl1.0_0~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstinsertbin1.0_0", rpm:"lib64gstinsertbin1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstinsertbin1.0_0", rpm:"lib64gstinsertbin1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstisoff1.0_0", rpm:"lib64gstisoff1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstisoff1.0_0", rpm:"lib64gstisoff1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstmpegts1.0_0", rpm:"lib64gstmpegts1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstmpegts1.0_0", rpm:"lib64gstmpegts1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography1.0_0", rpm:"lib64gstphotography1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography1.0_0", rpm:"lib64gstphotography1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer-gir1.0", rpm:"lib64gstplayer-gir1.0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer-gir1.0", rpm:"lib64gstplayer-gir1.0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer1.0_0", rpm:"lib64gstplayer1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer1.0_0", rpm:"lib64gstplayer1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad-gir1.0", rpm:"lib64gstreamer-plugins-bad-gir1.0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad-gir1.0", rpm:"lib64gstreamer-plugins-bad-gir1.0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad1.0-devel", rpm:"lib64gstreamer-plugins-bad1.0-devel~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad1.0-devel", rpm:"lib64gstreamer-plugins-bad1.0-devel~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base-gir1.0", rpm:"lib64gstreamer-plugins-base-gir1.0~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0-devel", rpm:"lib64gstreamer-plugins-base1.0-devel~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0_0", rpm:"lib64gstreamer-plugins-base1.0_0~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstsctp1.0_0", rpm:"lib64gstsctp1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstsctp1.0_0", rpm:"lib64gstsctp1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsturidownloader1.0_0", rpm:"lib64gsturidownloader1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsturidownloader1.0_0", rpm:"lib64gsturidownloader1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwayland1.0_0", rpm:"lib64gstwayland1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwayland1.0_0", rpm:"lib64gstwayland1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc-gir1.0", rpm:"lib64gstwebrtc-gir1.0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc-gir1.0", rpm:"lib64gstwebrtc-gir1.0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc1.0_0", rpm:"lib64gstwebrtc1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc1.0_0", rpm:"lib64gstwebrtc1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio1.0_0", rpm:"libgstbadaudio1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio1.0_0", rpm:"libgstbadaudio1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc1.0_0", rpm:"libgstbasecamerabinsrc1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc1.0_0", rpm:"libgstbasecamerabinsrc1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers1.0_0", rpm:"libgstcodecparsers1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers1.0_0", rpm:"libgstcodecparsers1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-gir1.0", rpm:"libgstgl-gir1.0~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl1.0_0", rpm:"libgstgl1.0_0~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin1.0_0", rpm:"libgstinsertbin1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin1.0_0", rpm:"libgstinsertbin1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff1.0_0", rpm:"libgstisoff1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff1.0_0", rpm:"libgstisoff1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts1.0_0", rpm:"libgstmpegts1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts1.0_0", rpm:"libgstmpegts1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography1.0_0", rpm:"libgstphotography1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography1.0_0", rpm:"libgstphotography1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-gir1.0", rpm:"libgstplayer-gir1.0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-gir1.0", rpm:"libgstplayer-gir1.0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer1.0_0", rpm:"libgstplayer1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer1.0_0", rpm:"libgstplayer1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad-gir1.0", rpm:"libgstreamer-plugins-bad-gir1.0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad-gir1.0", rpm:"libgstreamer-plugins-bad-gir1.0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad1.0-devel", rpm:"libgstreamer-plugins-bad1.0-devel~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad1.0-devel", rpm:"libgstreamer-plugins-bad1.0-devel~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base-gir1.0", rpm:"libgstreamer-plugins-base-gir1.0~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0-devel", rpm:"libgstreamer-plugins-base1.0-devel~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0_0", rpm:"libgstreamer-plugins-base1.0_0~1.16.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp1.0_0", rpm:"libgstsctp1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp1.0_0", rpm:"libgstsctp1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader1.0_0", rpm:"libgsturidownloader1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader1.0_0", rpm:"libgsturidownloader1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland1.0_0", rpm:"libgstwayland1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland1.0_0", rpm:"libgstwayland1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-gir1.0", rpm:"libgstwebrtc-gir1.0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-gir1.0", rpm:"libgstwebrtc-gir1.0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc1.0_0", rpm:"libgstwebrtc1.0_0~1.16.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc1.0_0", rpm:"libgstwebrtc1.0_0~1.16.0~1.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdparanoia", rpm:"gstreamer1.0-cdparanoia~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-curl", rpm:"gstreamer1.0-curl~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-curl", rpm:"gstreamer1.0-curl~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dash", rpm:"gstreamer1.0-dash~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dash", rpm:"gstreamer1.0-dash~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-de265", rpm:"gstreamer1.0-de265~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-faad", rpm:"gstreamer1.0-faad~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fdkaac", rpm:"gstreamer1.0-fdkaac~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fluidsynth", rpm:"gstreamer1.0-fluidsynth~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fluidsynth", rpm:"gstreamer1.0-fluidsynth~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gme", rpm:"gstreamer1.0-gme~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gme", rpm:"gstreamer1.0-gme~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gsm", rpm:"gstreamer1.0-gsm~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gsm", rpm:"gstreamer1.0-gsm~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ladspa", rpm:"gstreamer1.0-ladspa~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ladspa", rpm:"gstreamer1.0-ladspa~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libass", rpm:"gstreamer1.0-libass~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libass", rpm:"gstreamer1.0-libass~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libvisual", rpm:"gstreamer1.0-libvisual~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mms", rpm:"gstreamer1.0-mms~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mms", rpm:"gstreamer1.0-mms~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg2enc", rpm:"gstreamer1.0-mpeg2enc~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg2enc", rpm:"gstreamer1.0-mpeg2enc~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-neon", rpm:"gstreamer1.0-neon~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-neon", rpm:"gstreamer1.0-neon~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ofa", rpm:"gstreamer1.0-ofa~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ofa", rpm:"gstreamer1.0-ofa~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad", rpm:"gstreamer1.0-plugins-bad~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad", rpm:"gstreamer1.0-plugins-bad~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-base", rpm:"gstreamer1.0-plugins-base~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtmp", rpm:"gstreamer1.0-rtmp~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtmp", rpm:"gstreamer1.0-rtmp~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sbc", rpm:"gstreamer1.0-sbc~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sbc", rpm:"gstreamer1.0-sbc~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-smoothstreaming", rpm:"gstreamer1.0-smoothstreaming~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-smoothstreaming", rpm:"gstreamer1.0-smoothstreaming~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soundtouch", rpm:"gstreamer1.0-soundtouch~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soundtouch", rpm:"gstreamer1.0-soundtouch~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-srtp", rpm:"gstreamer1.0-srtp~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-srtp", rpm:"gstreamer1.0-srtp~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-transcoder", rpm:"gstreamer1.0-transcoder~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-transcoder", rpm:"gstreamer1.0-transcoder~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wildmidi", rpm:"gstreamer1.0-wildmidi~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wildmidi", rpm:"gstreamer1.0-wildmidi~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-x265", rpm:"gstreamer1.0-x265~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64girgstmpegts-gir1.0", rpm:"lib64girgstmpegts-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64girgstmpegts-gir1.0", rpm:"lib64girgstmpegts-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64girinsertbin-git1.0", rpm:"lib64girinsertbin-git1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64girinsertbin-git1.0", rpm:"lib64girinsertbin-git1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio-gir1.0", rpm:"lib64gstbadaudio-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio-gir1.0", rpm:"lib64gstbadaudio-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio1.0_0", rpm:"lib64gstbadaudio1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio1.0_0", rpm:"lib64gstbadaudio1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasecamerabinsrc1.0_0", rpm:"lib64gstbasecamerabinsrc1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasecamerabinsrc1.0_0", rpm:"lib64gstbasecamerabinsrc1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecparsers1.0_0", rpm:"lib64gstcodecparsers1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecparsers1.0_0", rpm:"lib64gstcodecparsers1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecs-gir1.0", rpm:"lib64gstcodecs-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecs-gir1.0", rpm:"lib64gstcodecs-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecs1.0_0", rpm:"lib64gstcodecs1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecs1.0_0", rpm:"lib64gstcodecs1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl-gir1.0", rpm:"lib64gstgl-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl1.0_0", rpm:"lib64gstgl1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstinsertbin1.0_0", rpm:"lib64gstinsertbin1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstinsertbin1.0_0", rpm:"lib64gstinsertbin1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstisoff1.0_0", rpm:"lib64gstisoff1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstisoff1.0_0", rpm:"lib64gstisoff1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstmpegts1.0_0", rpm:"lib64gstmpegts1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstmpegts1.0_0", rpm:"lib64gstmpegts1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography1.0_0", rpm:"lib64gstphotography1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography1.0_0", rpm:"lib64gstphotography1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer-gir1.0", rpm:"lib64gstplayer-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer-gir1.0", rpm:"lib64gstplayer-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer1.0_0", rpm:"lib64gstplayer1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer1.0_0", rpm:"lib64gstplayer1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad1.0-devel", rpm:"lib64gstreamer-plugins-bad1.0-devel~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad1.0-devel", rpm:"lib64gstreamer-plugins-bad1.0-devel~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base-gir1.0", rpm:"lib64gstreamer-plugins-base-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0-devel", rpm:"lib64gstreamer-plugins-base1.0-devel~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0_0", rpm:"lib64gstreamer-plugins-base1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstsctp1.0_0", rpm:"lib64gstsctp1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstsctp1.0_0", rpm:"lib64gstsctp1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder-devel", rpm:"lib64gsttranscoder-devel~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder-devel", rpm:"lib64gsttranscoder-devel~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder-gir1.0", rpm:"lib64gsttranscoder-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder-gir1.0", rpm:"lib64gsttranscoder-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder1.0_0", rpm:"lib64gsttranscoder1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder1.0_0", rpm:"lib64gsttranscoder1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsturidownloader1.0_0", rpm:"lib64gsturidownloader1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsturidownloader1.0_0", rpm:"lib64gsturidownloader1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwayland1.0_0", rpm:"lib64gstwayland1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwayland1.0_0", rpm:"lib64gstwayland1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc-gir1.0", rpm:"lib64gstwebrtc-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc-gir1.0", rpm:"lib64gstwebrtc-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc1.0_0", rpm:"lib64gstwebrtc1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc1.0_0", rpm:"lib64gstwebrtc1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgirgstmpegts-gir1.0", rpm:"libgirgstmpegts-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgirgstmpegts-gir1.0", rpm:"libgirgstmpegts-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgirinsertbin-git1.0", rpm:"libgirinsertbin-git1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgirinsertbin-git1.0", rpm:"libgirinsertbin-git1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-gir1.0", rpm:"libgstbadaudio-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-gir1.0", rpm:"libgstbadaudio-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio1.0_0", rpm:"libgstbadaudio1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio1.0_0", rpm:"libgstbadaudio1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc1.0_0", rpm:"libgstbasecamerabinsrc1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc1.0_0", rpm:"libgstbasecamerabinsrc1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers1.0_0", rpm:"libgstcodecparsers1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers1.0_0", rpm:"libgstcodecparsers1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs-gir1.0", rpm:"libgstcodecs-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs-gir1.0", rpm:"libgstcodecs-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs1.0_0", rpm:"libgstcodecs1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs1.0_0", rpm:"libgstcodecs1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-gir1.0", rpm:"libgstgl-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl1.0_0", rpm:"libgstgl1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin1.0_0", rpm:"libgstinsertbin1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin1.0_0", rpm:"libgstinsertbin1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff1.0_0", rpm:"libgstisoff1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff1.0_0", rpm:"libgstisoff1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts1.0_0", rpm:"libgstmpegts1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts1.0_0", rpm:"libgstmpegts1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography1.0_0", rpm:"libgstphotography1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography1.0_0", rpm:"libgstphotography1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-gir1.0", rpm:"libgstplayer-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-gir1.0", rpm:"libgstplayer-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer1.0_0", rpm:"libgstplayer1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer1.0_0", rpm:"libgstplayer1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad1.0-devel", rpm:"libgstreamer-plugins-bad1.0-devel~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad1.0-devel", rpm:"libgstreamer-plugins-bad1.0-devel~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base-gir1.0", rpm:"libgstreamer-plugins-base-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0-devel", rpm:"libgstreamer-plugins-base1.0-devel~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0_0", rpm:"libgstreamer-plugins-base1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp1.0_0", rpm:"libgstsctp1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp1.0_0", rpm:"libgstsctp1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder-devel", rpm:"libgsttranscoder-devel~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder-devel", rpm:"libgsttranscoder-devel~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder-gir1.0", rpm:"libgsttranscoder-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder-gir1.0", rpm:"libgsttranscoder-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder1.0_0", rpm:"libgsttranscoder1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder1.0_0", rpm:"libgsttranscoder1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader1.0_0", rpm:"libgsturidownloader1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader1.0_0", rpm:"libgsturidownloader1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland1.0_0", rpm:"libgstwayland1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland1.0_0", rpm:"libgstwayland1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-gir1.0", rpm:"libgstwebrtc-gir1.0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-gir1.0", rpm:"libgstwebrtc-gir1.0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc1.0_0", rpm:"libgstwebrtc1.0_0~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc1.0_0", rpm:"libgstwebrtc1.0_0~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
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
