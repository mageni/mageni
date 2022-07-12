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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0059");
  script_cve_id("CVE-2016-2827", "CVE-2016-5257", "CVE-2016-5270", "CVE-2016-5271", "CVE-2016-5272", "CVE-2016-5274", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5284");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-12 01:29:00 +0000 (Tue, 12 Jun 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0059)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0059");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0059.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20025");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-85/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape' package(s) announced via the MGASA-2017-0059 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated Iceape packages derived from Seamonkey include security fixes from
Mozilla Firefox:

Heap-based buffer overflow in the
nsCaseTransformTextRunFactory::TransformString function in Seamonkey
before 2.46 allows remote attackers to cause a denial of service (boolean
out-of-bounds write) or possibly have unspecified other impact via Unicode
characters that are mishandled during text conversion. (CVE-2016-5270)

The PropertyProvider::GetSpacingInternal function in Seamonkey before 2.46
allows remote attackers to cause a denial of service (out-of-bounds read
and application crash) via text runs in conjunction with a
'display: contents' Cascading Style Sheets (CSS) property. (CVE-2016-5271)

The nsImageGeometryMixin class in Seamonkey before 2.46 does not properly
perform a cast of an unspecified variable during handling of INPUT
elements, which allows remote attackers to execute arbitrary code via a
crafted web site. (CVE-2016-5272)

Use-after-free vulnerability in the
mozilla::a11y::DocAccessible::ProcessInvalidationList function in
Seamonkey before 2.46 allows remote attackers to execute arbitrary code
or cause a denial of service (heap memory corruption) via an aria-owns
attribute. (CVE-2016-5276)

Use-after-free vulnerability in the nsFrameManager::CaptureFrameState
function in Seamonkey before 2.46 allows remote attackers to execute
arbitrary code by leveraging improper interaction between restyling and
the Web Animations model implementation. (CVE-2016-5274)

Use-after-free vulnerability in the nsRefreshDriver::Tick function in
Seamonkey before 2.46 allows remote attackers to execute arbitrary code or
cause a denial of service (heap memory corruption) by leveraging improper
interaction between timeline destruction and the Web Animations model
implementation. (CVE-2016-5277)

Heap-based buffer overflow in the nsBMPEncoder::AddImageFrame function in
Seamonkey before 2.46 allows remote attackers to execute arbitrary code
via a crafted image data that is mishandled during the encoding of an
image frame to an image. (CVE-2016-5278)

Use-after-free vulnerability in the
mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap function in
Seamonkey before 2.46 allows remote attackers to execute arbitrary code
via bidirectional text. (CVE-2016-5280)

Use-after-free vulnerability in the DOMSVGLength class in Seamonkey before
2.46 allows remote attackers to execute arbitrary code by leveraging
improper interaction between JavaScript code and an SVG document.
(CVE-2016-5281)

Seamonkey before 2.46 relies on unintended expiration dates for Preloaded
Public Key Pinning, which allows man-in-the-middle attackers to spoof
add-on updates by leveraging possession of an X.509 server certificate for
addons.mozilla.org signed by an arbitrary built-in Certification
Authority. (CVE-2016-5284)

Multiple unspecified vulnerabilities in the browser engine in Seamonkey
before 2.46 allow ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.46~1.mga5", rls:"MAGEIA5"))) {
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
