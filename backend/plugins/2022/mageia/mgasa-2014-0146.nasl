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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0146");
  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1496", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 13:48:00 +0000 (Tue, 11 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0146)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0146");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0146.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-15.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-16.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-17.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-18.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-19.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-20.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-22.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-23.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-26.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-27.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-28.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-29.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-30.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-31.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-32.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13072");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape, iceape' package(s) announced via the MGASA-2014-0146 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated iceape packages fix security issues:

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 28.0, Firefox ESR 24.x before 24.4, Thunderbird before 24.4,
and SeaMonkey before 2.25 allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute arbitrary
code via unknown vectors. (CVE-2014-1493)

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 28.0 and SeaMonkey before 2.25 allow remote attackers to cause
a denial of service (memory corruption and application crash) or possibly
execute arbitrary code via unknown vectors. (CVE-2014-1494)

Mozilla Firefox before 28.0, Firefox ESR 24.x before 24.4, Thunderbird
before 24.4, and SeaMonkey before 2.25 might allow local users to gain
privileges by modifying the extracted Mar contents during an update.
(CVE-2014-1496)

mozilla::WaveReader::DecodeAudioData function in Mozilla Firefox before
28.0, Firefox ESR 24.x before 24.4, Thunderbird before 24.4, and SeaMonkey
before 2.25 allows remote attackers to obtain sensitive information from
process heap memory, cause a denial of service (out-of-bounds read and
application crash), or possibly have unspecified other impact via a crafted
WAV file. (CVE-2014-1497)

The crypto.generateCRMFRequest method in Mozilla Firefox before 28.0 and
SeaMonkey before 2.25 does not properly validate a certain key type, which
allows remote attackers to cause a denial of service (application crash)
via vectors that trigger generation of a key that supports the Elliptic
Curve ec-dual-use algorithm. (CVE-2014-1498)

Mozilla Firefox before 28.0 and SeaMonkey before 2.25 allow remote
attackers to spoof the domain name in the WebRTC (1) camera or (2)
microphone permission prompt by triggering navigation at a certain time
during generation of this prompt. (CVE-2014-1499)

Mozilla Firefox before 28.0 and SeaMonkey before 2.25 allow remote
attackers to cause a denial of service (resource consumption and
application hang) via onbeforeunload events that trigger background
JavaScript execution. (CVE-2014-1500)

The (1) WebGL.compressedTexImage2D and (2) WebGL.compressedTexSubImage2D
functions in Mozilla Firefox before 28.0 and SeaMonkey before 2.25 allow
remote attackers to bypass the Same Origin Policy and render content in a
different domain via unspecified vectors. (CVE-2014-1502)

The session-restore feature in Mozilla Firefox before 28.0 and SeaMonkey
before 2.25 does not consider the Content Security Policy of a data: URL,
which makes it easier for remote attackers to conduct cross-site scripting
(XSS) attacks via a crafted document that is accessed after a browser
restart. (CVE-2014-1504)

The libxul.so!gfxContext::Polygon function in Mozilla Firefox before 28.0,
Firefox ESR 24.x before 24.4, Thunderbird before 24.4, and SeaMonkey before
2.25 allows remote attackers to obtain sensitive ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape, iceape' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.25~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.25~1.mga4", rls:"MAGEIA4"))) {
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
