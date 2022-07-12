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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0048");
  script_cve_id("CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5612", "CVE-2013-5613", "CVE-2013-5614", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-5619", "CVE-2013-6671", "CVE-2013-6672", "CVE-2013-6673", "CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479", "CVE-2014-1480", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1485", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 14:42:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0048)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0048");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0048.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-104.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-106.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-107.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-108.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-109.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-110.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-111.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-112.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-113.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-114.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-115.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-02.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-03.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-04.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-05.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-07.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-08.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-09.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-11.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-13.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12650");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape, iceape' package(s) announced via the MGASA-2014-0048 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated iceape packages fix security issues:

Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox
before 26.0, Firefox ESR 24.x before 24.2, Thunderbird before 24.2, and SeaMonkey
before 2.23 allow remote attackers to cause a denial of service (memory corruption
and application crash) or possibly execute arbitrary code via unknown vectors.
(CVE-2013-5609)

Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox
before 26.0 and SeaMonkey before 2.23 allow remote attackers to cause a denial
of service (memory corruption and application crash) or possibly execute arbitrary
code via unknown vectors. (CVE-2013-5610)

Cross-site scripting (XSS) vulnerability in Mozilla Firefox before 26.0 and
SeaMonkey before 2.23 makes it easier for remote attackers to inject arbitrary
web script or HTML by leveraging a Same Origin Policy violation triggered by
lack of a charset parameter in a Content-Type HTTP header. (CVE-2013-5612)

Mozilla Firefox before 26.0 and SeaMonkey before 2.23 do not properly consider
the sandbox attribute of an IFRAME element during processing of a contained
OBJECT element, which allows remote attackers to bypass intended sandbox
restrictions via a crafted web site. (CVE-2013-5614)

Use-after-free vulnerability in the nsEventListenerManager::HandleEventSubType
function in Mozilla Firefox before 26.0, Firefox ESR 24.x before 24.2,
Thunderbird before 24.2, and SeaMonkey before 2.23 allows remote attackers to
execute arbitrary code or cause a denial of service (heap memory corruption)
via vectors related to mListeners event listeners. (CVE-2013-5616)

Use-after-free vulnerability in the nsNodeUtils::LastRelease function in the
table-editing user interface in the editor component in Mozilla Firefox before
26.0, Firefox ESR 24.x before 24.2, Thunderbird before 24.2, and SeaMonkey
before 2.23 allows remote attackers to execute arbitrary code by triggering
improper garbage collection. (CVE-2013-5618)

Multiple integer overflows in the binary-search implementation in SpiderMonkey
in Mozilla Firefox before 26.0 and SeaMonkey before 2.23 might allow remote
attackers to cause a denial of service (out-of-bounds array access) or possibly
have unspecified other impact via crafted JavaScript code. (CVE-2013-5619)

The nsGfxScrollFrameInner::IsLTR function in Mozilla Firefox before 26.0,
Firefox ESR 24.x before 24.2, Thunderbird before 24.2, and SeaMonkey before
2.23 allows remote attackers to execute arbitrary code via crafted use of
JavaScript code for ordered list elements. (CVE-2013-6671)

Mozilla Firefox before 26.0 and SeaMonkey before 2.23 on Linux allow user-assisted
remote attackers to read clipboard data by leveraging certain middle-click
paste operations. (CVE-2013-6672)

Mozilla Firefox before 26.0, Firefox ESR 24.x before 24.2, Thunderbird before
24.2, and SeaMonkey before 2.23 do not recognize a user's removal of ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.24~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.24~1.mga4", rls:"MAGEIA4"))) {
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
