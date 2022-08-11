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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0331");
  script_cve_id("CVE-2017-9258", "CVE-2017-9259", "CVE-2017-9260");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0331)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0331");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0331.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23323");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/DBNLS5JI6AFPGYDJHBRYWMSVRPRNVQCN/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'soundtouch' package(s) announced via the MGASA-2018-0331 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated soundtouch package fixes security vulnerabilities:

The TDStretch::processSamples function in source/SoundTouch/TDStretch.cpp
in SoundTouch 1.9.2 allows remote attackers to cause a denial of service
(infinite loop and CPU consumption) via a crafted wav file (CVE-2017-9258).

The TDStretch::acceptNewOverlapLength function in source/SoundTouch/
TDStretch.cpp in SoundTouch 1.9.2 allows remote attackers to cause a denial
of service (memory allocation error and application crash) via a crafted
wav file (CVE-2017-9259).

The TDStretchSSE::calcCrossCorr function in source/SoundTouch/
sse_optimized.cpp in SoundTouch 1.9.2 allows remote attackers to cause a
denial of service (heap-based buffer over-read and application crash) via
a crafted wav file (CVE-2017-9260).");

  script_tag(name:"affected", value:"'soundtouch' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64soundtouch-devel", rpm:"lib64soundtouch-devel~1.9.2~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soundtouch1", rpm:"lib64soundtouch1~1.9.2~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoundtouch-devel", rpm:"libsoundtouch-devel~1.9.2~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoundtouch1", rpm:"libsoundtouch1~1.9.2~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"soundtouch", rpm:"soundtouch~1.9.2~2.1.mga6", rls:"MAGEIA6"))) {
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
