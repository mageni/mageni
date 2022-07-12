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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0012");
  script_cve_id("CVE-2016-9445", "CVE-2016-9446", "CVE-2016-9447", "CVE-2016-9809", "CVE-2016-9812", "CVE-2016-9813", "CVE-2017-5843", "CVE-2017-5848");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0012");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0012.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20238");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19802");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19814");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3713");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/11/18/13");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3717");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/11/18/12");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/12/05/8");
  script_xref(name:"URL", value:"https://lwn.net/Vulnerabilities/708524/");
  script_xref(name:"URL", value:"https://lwn.net/Vulnerabilities/708873/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IQKP5AYCCUOV4CJ6YAVAIDLWZRXEY7JG/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3818");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer0.10-plugins-bad, gstreamer0.10-plugins-bad, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-bad' package(s) announced via the MGASA-2018-0012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Evans discovered that the GStreamer plugin to decode VMware screen
capture files allowed the execution of arbitrary code (CVE-2016-9445,
CVE-2016-9446).

Chris Evans discovered that the GStreamer 0.10 plugin to decode NES Sound
Format files allowed the execution of arbitrary code (CVE-2016-9447).

Hanno Boeck discovered multiple vulnerabilities in the GStreamer media
framework and its codecs and demuxers, which may result in denial of
service or the execution of arbitrary code if a malformed media file is
opened (CVE-2016-9809, CVE-2016-9812, CVE-2016-9813, CVE-2017-5843,
CVE-2017-5848).

The gstreamer0.10-plugins-bad package was affected by CVE-2016-9445,
CVE-2016-9446, CVE-2016-9447, CVE-2016-9809, CVE-2017-5843, and
CVE-2017-5848).

The gstreamer1.0-plugins-bad package was affected by CVE-2016-9445,
CVE-2016-9446, CVE-2016-9809, CVE-2016-9812, CVE-2016-9813, CVE-2017-5843,
and CVE-2017-5848.");

  script_tag(name:"affected", value:"'gstreamer0.10-plugins-bad, gstreamer0.10-plugins-bad, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-bad' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-celt", rpm:"gstreamer0.10-celt~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-celt", rpm:"gstreamer0.10-celt~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-cog", rpm:"gstreamer0.10-cog~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-cog", rpm:"gstreamer0.10-cog~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-curl", rpm:"gstreamer0.10-curl~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-curl", rpm:"gstreamer0.10-curl~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dc1394", rpm:"gstreamer0.10-dc1394~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dc1394", rpm:"gstreamer0.10-dc1394~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dirac", rpm:"gstreamer0.10-dirac~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dirac", rpm:"gstreamer0.10-dirac~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-directfb", rpm:"gstreamer0.10-directfb~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-directfb", rpm:"gstreamer0.10-directfb~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dts", rpm:"gstreamer0.10-dts~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-faad", rpm:"gstreamer0.10-faad~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-gme", rpm:"gstreamer0.10-gme~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-gme", rpm:"gstreamer0.10-gme~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-gsm", rpm:"gstreamer0.10-gsm~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-gsm", rpm:"gstreamer0.10-gsm~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-jp2k", rpm:"gstreamer0.10-jp2k~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-jp2k", rpm:"gstreamer0.10-jp2k~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-kate", rpm:"gstreamer0.10-kate~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-kate", rpm:"gstreamer0.10-kate~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-ladspa", rpm:"gstreamer0.10-ladspa~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-ladspa", rpm:"gstreamer0.10-ladspa~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-libass", rpm:"gstreamer0.10-libass~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-libass", rpm:"gstreamer0.10-libass~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mms", rpm:"gstreamer0.10-mms~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mms", rpm:"gstreamer0.10-mms~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mpeg2enc", rpm:"gstreamer0.10-mpeg2enc~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mpeg2enc", rpm:"gstreamer0.10-mpeg2enc~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-musepack", rpm:"gstreamer0.10-musepack~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-musepack", rpm:"gstreamer0.10-musepack~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-nas", rpm:"gstreamer0.10-nas~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-nas", rpm:"gstreamer0.10-nas~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-neon", rpm:"gstreamer0.10-neon~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-neon", rpm:"gstreamer0.10-neon~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-ofa", rpm:"gstreamer0.10-ofa~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-ofa", rpm:"gstreamer0.10-ofa~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-bad", rpm:"gstreamer0.10-plugins-bad~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-bad", rpm:"gstreamer0.10-plugins-bad~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-bad-doc", rpm:"gstreamer0.10-plugins-bad-doc~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-bad-doc", rpm:"gstreamer0.10-plugins-bad-doc~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-resindvd", rpm:"gstreamer0.10-resindvd~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-resindvd", rpm:"gstreamer0.10-resindvd~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-rsvg", rpm:"gstreamer0.10-rsvg~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-rsvg", rpm:"gstreamer0.10-rsvg~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-rtmp", rpm:"gstreamer0.10-rtmp~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-rtmp", rpm:"gstreamer0.10-rtmp~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-schroedinger", rpm:"gstreamer0.10-schroedinger~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-schroedinger", rpm:"gstreamer0.10-schroedinger~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-soundtouch", rpm:"gstreamer0.10-soundtouch~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-soundtouch", rpm:"gstreamer0.10-soundtouch~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-vdpau", rpm:"gstreamer0.10-vdpau~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-vdpau", rpm:"gstreamer0.10-vdpau~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-voip", rpm:"gstreamer0.10-voip~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-voip", rpm:"gstreamer0.10-voip~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-vp8", rpm:"gstreamer0.10-vp8~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-vp8", rpm:"gstreamer0.10-vp8~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-wildmidi", rpm:"gstreamer0.10-wildmidi~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-wildmidi", rpm:"gstreamer0.10-wildmidi~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-xvid", rpm:"gstreamer0.10-xvid~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-curl", rpm:"gstreamer1.0-curl~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-curl", rpm:"gstreamer1.0-curl~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dash", rpm:"gstreamer1.0-dash~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dash", rpm:"gstreamer1.0-dash~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-directfb", rpm:"gstreamer1.0-directfb~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-directfb", rpm:"gstreamer1.0-directfb~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-faad", rpm:"gstreamer1.0-faad~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fluidsynth", rpm:"gstreamer1.0-fluidsynth~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fluidsynth", rpm:"gstreamer1.0-fluidsynth~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gme", rpm:"gstreamer1.0-gme~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gme", rpm:"gstreamer1.0-gme~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gsm", rpm:"gstreamer1.0-gsm~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gsm", rpm:"gstreamer1.0-gsm~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ladspa", rpm:"gstreamer1.0-ladspa~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ladspa", rpm:"gstreamer1.0-ladspa~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libass", rpm:"gstreamer1.0-libass~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libass", rpm:"gstreamer1.0-libass~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mms", rpm:"gstreamer1.0-mms~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mms", rpm:"gstreamer1.0-mms~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg2enc", rpm:"gstreamer1.0-mpeg2enc~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg2enc", rpm:"gstreamer1.0-mpeg2enc~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-neon", rpm:"gstreamer1.0-neon~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-neon", rpm:"gstreamer1.0-neon~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ofa", rpm:"gstreamer1.0-ofa~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ofa", rpm:"gstreamer1.0-ofa~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-opencv", rpm:"gstreamer1.0-opencv~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-opencv", rpm:"gstreamer1.0-opencv~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad", rpm:"gstreamer1.0-plugins-bad~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad", rpm:"gstreamer1.0-plugins-bad~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad-doc", rpm:"gstreamer1.0-plugins-bad-doc~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad-doc", rpm:"gstreamer1.0-plugins-bad-doc~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtmp", rpm:"gstreamer1.0-rtmp~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtmp", rpm:"gstreamer1.0-rtmp~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sbc", rpm:"gstreamer1.0-sbc~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sbc", rpm:"gstreamer1.0-sbc~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-schroedinger", rpm:"gstreamer1.0-schroedinger~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-schroedinger", rpm:"gstreamer1.0-schroedinger~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-smoothstreaming", rpm:"gstreamer1.0-smoothstreaming~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-smoothstreaming", rpm:"gstreamer1.0-smoothstreaming~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soundtouch", rpm:"gstreamer1.0-soundtouch~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soundtouch", rpm:"gstreamer1.0-soundtouch~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-spandsp", rpm:"gstreamer1.0-spandsp~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-spandsp", rpm:"gstreamer1.0-spandsp~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-srtp", rpm:"gstreamer1.0-srtp~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-srtp", rpm:"gstreamer1.0-srtp~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wildmidi", rpm:"gstreamer1.0-wildmidi~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wildmidi", rpm:"gstreamer1.0-wildmidi~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadbase1.0_0", rpm:"lib64gstbadbase1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadbase1.0_0", rpm:"lib64gstbadbase1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadvideo1.0_0", rpm:"lib64gstbadvideo1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadvideo1.0_0", rpm:"lib64gstbadvideo1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasecamerabinsrc1.0_0", rpm:"lib64gstbasecamerabinsrc1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasecamerabinsrc1.0_0", rpm:"lib64gstbasecamerabinsrc1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasevideo-devel", rpm:"lib64gstbasevideo-devel~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasevideo-devel", rpm:"lib64gstbasevideo-devel~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasevideo0.10_0", rpm:"lib64gstbasevideo0.10_0~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasevideo0.10_0", rpm:"lib64gstbasevideo0.10_0~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecparsers1.0_0", rpm:"lib64gstcodecparsers1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecparsers1.0_0", rpm:"lib64gstcodecparsers1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl1.0_0", rpm:"lib64gstgl1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl1.0_0", rpm:"lib64gstgl1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstinsertbin1.0_0", rpm:"lib64gstinsertbin1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstinsertbin1.0_0", rpm:"lib64gstinsertbin1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstmpegts1.0_0", rpm:"lib64gstmpegts1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstmpegts1.0_0", rpm:"lib64gstmpegts1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography-devel", rpm:"lib64gstphotography-devel~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography-devel", rpm:"lib64gstphotography-devel~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography0.10_0", rpm:"lib64gstphotography0.10_0~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography0.10_0", rpm:"lib64gstphotography0.10_0~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography1.0_0", rpm:"lib64gstphotography1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography1.0_0", rpm:"lib64gstphotography1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad-gir1.0", rpm:"lib64gstreamer-plugins-bad-gir1.0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad-gir1.0", rpm:"lib64gstreamer-plugins-bad-gir1.0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad1.0-devel", rpm:"lib64gstreamer-plugins-bad1.0-devel~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad1.0-devel", rpm:"lib64gstreamer-plugins-bad1.0-devel~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsturidownloader1.0_0", rpm:"lib64gsturidownloader1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsturidownloader1.0_0", rpm:"lib64gsturidownloader1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstvdp0.10_0", rpm:"lib64gstvdp0.10_0~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstvdp0.10_0", rpm:"lib64gstvdp0.10_0~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwayland1.0_0", rpm:"lib64gstwayland1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwayland1.0_0", rpm:"lib64gstwayland1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadbase1.0_0", rpm:"libgstbadbase1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadbase1.0_0", rpm:"libgstbadbase1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadvideo1.0_0", rpm:"libgstbadvideo1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadvideo1.0_0", rpm:"libgstbadvideo1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc1.0_0", rpm:"libgstbasecamerabinsrc1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc1.0_0", rpm:"libgstbasecamerabinsrc1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasevideo-devel", rpm:"libgstbasevideo-devel~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasevideo-devel", rpm:"libgstbasevideo-devel~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasevideo0.10_0", rpm:"libgstbasevideo0.10_0~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasevideo0.10_0", rpm:"libgstbasevideo0.10_0~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers1.0_0", rpm:"libgstcodecparsers1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers1.0_0", rpm:"libgstcodecparsers1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl1.0_0", rpm:"libgstgl1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl1.0_0", rpm:"libgstgl1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin1.0_0", rpm:"libgstinsertbin1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin1.0_0", rpm:"libgstinsertbin1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts1.0_0", rpm:"libgstmpegts1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts1.0_0", rpm:"libgstmpegts1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-devel", rpm:"libgstphotography-devel~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-devel", rpm:"libgstphotography-devel~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography0.10_0", rpm:"libgstphotography0.10_0~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography0.10_0", rpm:"libgstphotography0.10_0~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography1.0_0", rpm:"libgstphotography1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography1.0_0", rpm:"libgstphotography1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad-gir1.0", rpm:"libgstreamer-plugins-bad-gir1.0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad-gir1.0", rpm:"libgstreamer-plugins-bad-gir1.0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad1.0-devel", rpm:"libgstreamer-plugins-bad1.0-devel~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad1.0-devel", rpm:"libgstreamer-plugins-bad1.0-devel~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader1.0_0", rpm:"libgsturidownloader1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader1.0_0", rpm:"libgsturidownloader1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvdp0.10_0", rpm:"libgstvdp0.10_0~0.10.23~22.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvdp0.10_0", rpm:"libgstvdp0.10_0~0.10.23~22.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland1.0_0", rpm:"libgstwayland1.0_0~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland1.0_0", rpm:"libgstwayland1.0_0~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
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
