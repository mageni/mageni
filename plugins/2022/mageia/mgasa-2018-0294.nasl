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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0294");
  script_cve_id("CVE-2017-14160", "CVE-2018-10392", "CVE-2018-10393");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-28 00:15:00 +0000 (Thu, 28 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0294)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0294");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0294.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23145");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-05/msg00067.html");
  script_xref(name:"URL", value:"http://lists.suse.com/pipermail/sle-security-updates/2018-June/004158.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-06/msg00047.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvorbis, libvorbis' package(s) announced via the MGASA-2018-0294 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

The bark_noise_hybridmp function in psy.c in Xiph.Org libvorbis 1.3.5 allows
remote attackers to cause a denial of service (out-of-bounds access and
application crash) or possibly have unspecified other impact via a crafted mp4
file. (CVE-2017-14160)

mapping0_forward in mapping0.c in Xiph.Org libvorbis 1.3.6 does not validate the
number of channels, which allows remote attackers to cause a denial of service
(heap-based buffer overflow or over-read) or possibly have unspecified other
impact via a crafted file. (CVE-2018-10392)

bark_noise_hybridmp in psy.c in Xiph.Org libvorbis 1.3.6 has a stack-based
buffer over-read. (CVE-2018-10393)");

  script_tag(name:"affected", value:"'libvorbis, libvorbis' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbis-devel", rpm:"lib64vorbis-devel~1.3.5~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbis0", rpm:"lib64vorbis0~1.3.5~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbisenc2", rpm:"lib64vorbisenc2~1.3.5~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbisfile3", rpm:"lib64vorbisfile3~1.3.5~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis", rpm:"libvorbis~1.3.5~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.3.5~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0", rpm:"libvorbis0~1.3.5~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2", rpm:"libvorbisenc2~1.3.5~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3", rpm:"libvorbisfile3~1.3.5~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbis-devel", rpm:"lib64vorbis-devel~1.3.5~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbis0", rpm:"lib64vorbis0~1.3.5~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbisenc2", rpm:"lib64vorbisenc2~1.3.5~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbisfile3", rpm:"lib64vorbisfile3~1.3.5~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis", rpm:"libvorbis~1.3.5~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.3.5~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0", rpm:"libvorbis0~1.3.5~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2", rpm:"libvorbisenc2~1.3.5~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3", rpm:"libvorbisfile3~1.3.5~2.4.mga6", rls:"MAGEIA6"))) {
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
