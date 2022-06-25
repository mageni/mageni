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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0187");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2021-0187)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0187");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0187.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28685");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2021-0002.html");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2021-0003.html");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2021-0004.html");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2021-0005.html");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/releases/1.18/#1.18.4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer1.0-libav, gstreamer1.0-libav, gstreamer1.0-plugins-good, gstreamer1.0-plugins-good, gstreamer1.0-plugins-ugly, gstreamer1.0-plugins-ugly, gstreamer1.0-plugins-ugly, gstreamer1.0-plugins-ugly' package(s) announced via the MGASA-2021-0187 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GStreamer before 1.18.4 might access already-freed memory in error code
paths when demuxing certain malformed Matroska files (SA-2021-0002).

GStreamer before 1.18.4 might cause heap corruption when parsing certain
malformed Matroska files (SA-2021-0003).

GStreamer before 1.18.4 might do an out-of-bounds read when handling
certain RealMedia files or streams (SA-2021-0004).

GStreamer before 1.18.4 might cause stack corruptions with streams that
have more than 64 audio channels (SA-2021-0005).

It might be possible for a malicious third party to trigger a crash in
the application, but possibly also an arbitrary code execution with the
privileges of the target user.");

  script_tag(name:"affected", value:"'gstreamer1.0-libav, gstreamer1.0-libav, gstreamer1.0-plugins-good, gstreamer1.0-plugins-good, gstreamer1.0-plugins-ugly, gstreamer1.0-plugins-ugly, gstreamer1.0-plugins-ugly, gstreamer1.0-plugins-ugly' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-a52dec", rpm:"gstreamer1.0-a52dec~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-a52dec", rpm:"gstreamer1.0-a52dec~1.16.0~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-aalib", rpm:"gstreamer1.0-aalib~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-amrnb", rpm:"gstreamer1.0-amrnb~1.16.0~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-amrwbdec", rpm:"gstreamer1.0-amrwbdec~1.16.0~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-caca", rpm:"gstreamer1.0-caca~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdio", rpm:"gstreamer1.0-cdio~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdio", rpm:"gstreamer1.0-cdio~1.16.0~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dv", rpm:"gstreamer1.0-dv~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-flac", rpm:"gstreamer1.0-flac~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-jack", rpm:"gstreamer1.0-jack~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-lame", rpm:"gstreamer1.0-lame~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libav", rpm:"gstreamer1.0-libav~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg", rpm:"gstreamer1.0-mpeg~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg", rpm:"gstreamer1.0-mpeg~1.16.0~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-good", rpm:"gstreamer1.0-plugins-good~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-ugly", rpm:"gstreamer1.0-plugins-ugly~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-ugly", rpm:"gstreamer1.0-plugins-ugly~1.16.0~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-pulse", rpm:"gstreamer1.0-pulse~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-raw1394", rpm:"gstreamer1.0-raw1394~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sid", rpm:"gstreamer1.0-sid~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sid", rpm:"gstreamer1.0-sid~1.16.0~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soup", rpm:"gstreamer1.0-soup~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-speex", rpm:"gstreamer1.0-speex~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-twolame", rpm:"gstreamer1.0-twolame~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-vp8", rpm:"gstreamer1.0-vp8~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wavpack", rpm:"gstreamer1.0-wavpack~1.16.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-x264", rpm:"gstreamer1.0-x264~1.16.0~1.1.mga7.tainted", rls:"MAGEIA7"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-a52dec", rpm:"gstreamer1.0-a52dec~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-a52dec", rpm:"gstreamer1.0-a52dec~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-aalib", rpm:"gstreamer1.0-aalib~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-amrnb", rpm:"gstreamer1.0-amrnb~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-amrwbdec", rpm:"gstreamer1.0-amrwbdec~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-caca", rpm:"gstreamer1.0-caca~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdio", rpm:"gstreamer1.0-cdio~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdio", rpm:"gstreamer1.0-cdio~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dv", rpm:"gstreamer1.0-dv~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-flac", rpm:"gstreamer1.0-flac~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-jack", rpm:"gstreamer1.0-jack~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-lame", rpm:"gstreamer1.0-lame~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libav", rpm:"gstreamer1.0-libav~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg", rpm:"gstreamer1.0-mpeg~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg", rpm:"gstreamer1.0-mpeg~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-good", rpm:"gstreamer1.0-plugins-good~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-ugly", rpm:"gstreamer1.0-plugins-ugly~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-ugly", rpm:"gstreamer1.0-plugins-ugly~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-pulse", rpm:"gstreamer1.0-pulse~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-raw1394", rpm:"gstreamer1.0-raw1394~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sid", rpm:"gstreamer1.0-sid~1.18.3~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sid", rpm:"gstreamer1.0-sid~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soup", rpm:"gstreamer1.0-soup~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-speex", rpm:"gstreamer1.0-speex~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-twolame", rpm:"gstreamer1.0-twolame~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-vp8", rpm:"gstreamer1.0-vp8~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wavpack", rpm:"gstreamer1.0-wavpack~1.18.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-x264", rpm:"gstreamer1.0-x264~1.18.3~1.1.mga8.tainted", rls:"MAGEIA8"))) {
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
