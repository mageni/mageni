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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0259");
  script_cve_id("CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1522", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 17:35:00 +0000 (Thu, 06 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0259)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0259");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0259.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-34.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-36.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-37.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-38.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-39.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-42.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-43.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-44.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-46.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-47.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13330");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape, iceape' package(s) announced via the MGASA-2014-0259 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated iceape packages fix security issues:

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 29.0, Firefox ESR 24.x before 24.5, Thunderbird before
24.5, and SeaMonkey before 2.26 allow remote attackers to cause a denial
of service (memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors. (CVE-2014-1518)

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 29.0 and SeaMonkey before 2.26 allow remote attackers to
cause a denial of service (memory corruption and application crash) or
possibly execute arbitrary code via unknown vectors. (CVE-2014-1519)

The mozilla::dom::OscillatorNodeEngine::ComputeCustom function in the Web
Audio subsystem in Mozilla Firefox before 29.0 and SeaMonkey before 2.26
allows remote attackers to execute arbitrary code or cause a denial of
service (out-of-bounds read, memory corruption, and application crash)
via crafted content. (CVE-2014-1522)

Heap-based buffer overflow in the read_u32 function in Mozilla Firefox
before 29.0, Firefox ESR 24.x before 24.5, Thunderbird before 24.5, and
SeaMonkey before 2.26 allows remote attackers to cause a denial of service
(out-of-bounds read and application crash) via a crafted JPEG image.
(CVE-2014-1523)

The nsXBLProtoImpl::InstallImplementation function in Mozilla Firefox
before 29.0, Firefox ESR 24.x before 24.5, Thunderbird before 24.5, and
SeaMonkey before 2.26 does not properly check whether objects are XBL
objects, which allows remote attackers to execute arbitrary code or cause
a denial of service (buffer overflow) via crafted JavaScript code that
accesses a non-XBL object as if it were an XBL object. (CVE-2014-1524)

The mozilla::dom::TextTrack::AddCue function in Mozilla Firefox before
29.0 and SeaMonkey before 2.26 does not properly perform garbage
collection for Text Track Manager variables, which allows remote
attackers to execute arbitrary code or cause a denial of service
(use-after-free and heap memory corruption) via a crafted VIDEO element
in an HTML document. (CVE-2014-1525)

The Web Notification API in Mozilla Firefox before 29.0, Firefox ESR 24.x
before 24.5, Thunderbird before 24.5, and SeaMonkey before 2.26 allows
remote attackers to bypass intended source-component restrictions and
execute arbitrary JavaScript code in a privileged context via a crafted
web page for which Notification.permission is granted. (CVE-2014-1529)

The docshell implementation in Mozilla Firefox before 29.0, Firefox ESR
24.x before 24.5, Thunderbird before 24.5, and SeaMonkey before 2.26
allows remote attackers to trigger the loading of a URL with a spoofed
baseURI property, and conduct cross-site scripting (XSS) attacks, via a
crafted web site that performs history navigation. (CVE-2014-1530)

Use-after-free vulnerability in the nsGenericHTMLElement::
GetWidthHeightForImage function in Mozilla ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.26~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.26~1.mga4", rls:"MAGEIA4"))) {
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
