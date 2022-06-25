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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2449");
  script_cve_id("CVE-2017-9258", "CVE-2017-9259", "CVE-2017-9260", "CVE-2018-1000223", "CVE-2018-14044", "CVE-2018-17096");
  script_tag(name:"creation_date", value:"2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)");
  script_version("2021-09-15T02:24:22+0000");
  script_tag(name:"last_modification", value:"2021-09-15 10:20:43 +0000 (Wed, 15 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-15 16:17:00 +0000 (Mon, 15 Oct 2018)");

  script_name("Huawei EulerOS: Security Advisory for soundtouch (EulerOS-SA-2021-2449)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2449");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2449");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'soundtouch' package(s) announced via the EulerOS-SA-2021-2449 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The BPMDetect class in BPMDetect.cpp in libSoundTouch.a in Olli Parviainen SoundTouch 2.0 allows remote attackers to cause a denial of service (assertion failure and application exit), as demonstrated by SoundStretch.(CVE-2018-17096)

The TDStretchSSE::calcCrossCorr function in source/SoundTouch/sse_optimized.cpp in SoundTouch 1.9.2 allows remote attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted wav file.(CVE-2017-9260)

The TDStretch::processSamples function in source/SoundTouch/TDStretch.cpp in SoundTouch 1.9.2 allows remote attackers to cause a denial of service (infinite loop and CPU consumption) via a crafted wav file.(CVE-2017-9258)

The TDStretch::acceptNewOverlapLength function in source/SoundTouch/TDStretch.cpp in SoundTouch 1.9.2 allows remote attackers to cause a denial of service (memory allocation error and application crash) via a crafted wav file.(CVE-2017-9259)

The RateTransposer::setChannels function in RateTransposer.cpp in libSoundTouch.a in Olli Parviainen SoundTouch 2.0 allows remote attackers to cause a denial of service (assertion failure and application exit), as demonstrated by SoundStretch.(CVE-2018-14044)

soundtouch version up to and including 2.0.0 contains a Buffer Overflow vulnerability in SoundStretch/WavFile.cpp:WavInFile::readHeaderBlock() that can result in arbitrary code execution. This attack appear to be exploitable via victim must open maliocius file in soundstretch utility.(CVE-2018-1000223)");

  script_tag(name:"affected", value:"'soundtouch' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"soundtouch", rpm:"soundtouch~1.4.0~9.h3", rls:"EULEROS-2.0SP2"))) {
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
