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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0013");
  script_cve_id("CVE-2016-9809", "CVE-2017-5843", "CVE-2017-5848");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0013)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0013");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0013.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20238");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3818");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer0.10-plugins-bad, gstreamer0.10-plugins-bad' package(s) announced via the MGASA-2018-0013 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Boeck discovered multiple vulnerabilities in the GStreamer media
framework and its codecs and demuxers, which may result in denial of service
or the execution of arbitrary code if a malformed media file is opened
(CVE-2016-9809, CVE-2017-5843, CVE-2017-5848).");

  script_tag(name:"affected", value:"'gstreamer0.10-plugins-bad, gstreamer0.10-plugins-bad' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-celt", rpm:"gstreamer0.10-celt~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-celt", rpm:"gstreamer0.10-celt~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-cog", rpm:"gstreamer0.10-cog~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-cog", rpm:"gstreamer0.10-cog~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-curl", rpm:"gstreamer0.10-curl~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-curl", rpm:"gstreamer0.10-curl~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dc1394", rpm:"gstreamer0.10-dc1394~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dc1394", rpm:"gstreamer0.10-dc1394~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dirac", rpm:"gstreamer0.10-dirac~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dirac", rpm:"gstreamer0.10-dirac~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dts", rpm:"gstreamer0.10-dts~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-faad", rpm:"gstreamer0.10-faad~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-gme", rpm:"gstreamer0.10-gme~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-gme", rpm:"gstreamer0.10-gme~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-gsm", rpm:"gstreamer0.10-gsm~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-gsm", rpm:"gstreamer0.10-gsm~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-jp2k", rpm:"gstreamer0.10-jp2k~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-jp2k", rpm:"gstreamer0.10-jp2k~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-kate", rpm:"gstreamer0.10-kate~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-kate", rpm:"gstreamer0.10-kate~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-ladspa", rpm:"gstreamer0.10-ladspa~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-ladspa", rpm:"gstreamer0.10-ladspa~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-libass", rpm:"gstreamer0.10-libass~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-libass", rpm:"gstreamer0.10-libass~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mms", rpm:"gstreamer0.10-mms~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mms", rpm:"gstreamer0.10-mms~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mpeg2enc", rpm:"gstreamer0.10-mpeg2enc~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mpeg2enc", rpm:"gstreamer0.10-mpeg2enc~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-musepack", rpm:"gstreamer0.10-musepack~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-musepack", rpm:"gstreamer0.10-musepack~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-nas", rpm:"gstreamer0.10-nas~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-nas", rpm:"gstreamer0.10-nas~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-neon", rpm:"gstreamer0.10-neon~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-neon", rpm:"gstreamer0.10-neon~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-ofa", rpm:"gstreamer0.10-ofa~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-ofa", rpm:"gstreamer0.10-ofa~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-bad", rpm:"gstreamer0.10-plugins-bad~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-bad", rpm:"gstreamer0.10-plugins-bad~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-bad-doc", rpm:"gstreamer0.10-plugins-bad-doc~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-bad-doc", rpm:"gstreamer0.10-plugins-bad-doc~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-resindvd", rpm:"gstreamer0.10-resindvd~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-resindvd", rpm:"gstreamer0.10-resindvd~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-rsvg", rpm:"gstreamer0.10-rsvg~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-rsvg", rpm:"gstreamer0.10-rsvg~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-rtmp", rpm:"gstreamer0.10-rtmp~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-rtmp", rpm:"gstreamer0.10-rtmp~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-schroedinger", rpm:"gstreamer0.10-schroedinger~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-schroedinger", rpm:"gstreamer0.10-schroedinger~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-soundtouch", rpm:"gstreamer0.10-soundtouch~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-soundtouch", rpm:"gstreamer0.10-soundtouch~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-vdpau", rpm:"gstreamer0.10-vdpau~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-vdpau", rpm:"gstreamer0.10-vdpau~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-voip", rpm:"gstreamer0.10-voip~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-voip", rpm:"gstreamer0.10-voip~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-vp8", rpm:"gstreamer0.10-vp8~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-vp8", rpm:"gstreamer0.10-vp8~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-wildmidi", rpm:"gstreamer0.10-wildmidi~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-wildmidi", rpm:"gstreamer0.10-wildmidi~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-xvid", rpm:"gstreamer0.10-xvid~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasevideo-devel", rpm:"lib64gstbasevideo-devel~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasevideo-devel", rpm:"lib64gstbasevideo-devel~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasevideo0.10_0", rpm:"lib64gstbasevideo0.10_0~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasevideo0.10_0", rpm:"lib64gstbasevideo0.10_0~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography-devel", rpm:"lib64gstphotography-devel~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography-devel", rpm:"lib64gstphotography-devel~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography0.10_0", rpm:"lib64gstphotography0.10_0~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography0.10_0", rpm:"lib64gstphotography0.10_0~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstvdp0.10_0", rpm:"lib64gstvdp0.10_0~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstvdp0.10_0", rpm:"lib64gstvdp0.10_0~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasevideo-devel", rpm:"libgstbasevideo-devel~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasevideo-devel", rpm:"libgstbasevideo-devel~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasevideo0.10_0", rpm:"libgstbasevideo0.10_0~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasevideo0.10_0", rpm:"libgstbasevideo0.10_0~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-devel", rpm:"libgstphotography-devel~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-devel", rpm:"libgstphotography-devel~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography0.10_0", rpm:"libgstphotography0.10_0~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography0.10_0", rpm:"libgstphotography0.10_0~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvdp0.10_0", rpm:"libgstvdp0.10_0~0.10.23~35.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvdp0.10_0", rpm:"libgstvdp0.10_0~0.10.23~35.1.mga6.tainted", rls:"MAGEIA6"))) {
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
