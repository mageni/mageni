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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0322");
  script_cve_id("CVE-2022-1920", "CVE-2022-1921", "CVE-2022-1922", "CVE-2022-1923", "CVE-2022-1924", "CVE-2022-1925", "CVE-2022-2122");
  script_tag(name:"creation_date", value:"2022-09-12 05:06:20 +0000 (Mon, 12 Sep 2022)");
  script_version("2022-09-12T10:18:03+0000");
  script_tag(name:"last_modification", value:"2022-09-12 10:18:03 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-26 22:30:00 +0000 (Tue, 26 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0322)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0322");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0322.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30728");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5555-1");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2022-0001.html");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2022-0002.html");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2022-0003.html");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2022-0004.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5204");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer1.0-plugins-good' package(s) announced via the MGASA-2022-0322 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GStreamer Good Plugins incorrectly handled certain
files. An attacker could possibly use this issue to execute arbitrary
code. (CVE-2022-1920, CVE-2022-1921)

It was discovered that GStreamer Good Plugins incorrectly handled certain
files. An attacker could possibly use this issue to cause a denial of
service or execute arbitrary code. (CVE-2022-1922, CVE-2022-1923,
CVE-2022-1924, CVE-2022-1925, CVE-2022-2122)");

  script_tag(name:"affected", value:"'gstreamer1.0-plugins-good' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-aalib", rpm:"gstreamer1.0-aalib~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-caca", rpm:"gstreamer1.0-caca~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dv", rpm:"gstreamer1.0-dv~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-flac", rpm:"gstreamer1.0-flac~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-jack", rpm:"gstreamer1.0-jack~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-lame", rpm:"gstreamer1.0-lame~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-good", rpm:"gstreamer1.0-plugins-good~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-pulse", rpm:"gstreamer1.0-pulse~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-raw1394", rpm:"gstreamer1.0-raw1394~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soup", rpm:"gstreamer1.0-soup~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-speex", rpm:"gstreamer1.0-speex~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-twolame", rpm:"gstreamer1.0-twolame~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-vp8", rpm:"gstreamer1.0-vp8~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wavpack", rpm:"gstreamer1.0-wavpack~1.18.5~1.1.mga8", rls:"MAGEIA8"))) {
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
