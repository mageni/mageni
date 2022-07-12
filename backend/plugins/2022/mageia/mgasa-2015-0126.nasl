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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0126");
  script_cve_id("CVE-2015-0817", "CVE-2015-0818", "CVE-2015-0820", "CVE-2015-0821", "CVE-2015-0822", "CVE-2015-0824", "CVE-2015-0825", "CVE-2015-0826", "CVE-2015-0827", "CVE-2015-0828", "CVE-2015-0829", "CVE-2015-0830", "CVE-2015-0831", "CVE-2015-0832", "CVE-2015-0835", "CVE-2015-0836");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 02:59:00 +0000 (Thu, 22 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0126)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0126");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0126.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15476");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-11/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-13/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-14/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-16/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-17/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-18/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-19/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-20/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-21/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-22/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-24/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-25/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-27/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-28/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape' package(s) announced via the MGASA-2015-0126 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated iceape packages fix security issues:

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 36.0 allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute arbitrary
code via unknown vectors. (CVE-2015-0835)

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 36.0, Firefox ESR 31.x before 31.5, and Thunderbird before
31.5 allow remote attackers to cause a denial of service (memory corruption
and application crash) or possibly execute arbitrary code via unknown
vectors. (CVE-2015-0836)

Mozilla Firefox before 36.0 does not properly recognize the equivalence of
domain names with and without a trailing . (dot) character, which allows
man-in-the-middle attackers to bypass the HPKP and HSTS protection
mechanisms by constructing a URL with this character and leveraging access
to an X.509 certificate for a domain with this character. (CVE-2015-0832)

The WebGL implementation in Mozilla Firefox before 36.0 does not properly
allocate memory for copying an unspecified string to a shader's compilation
log, which allows remote attackers to cause a denial of service
(application crash) via crafted WebGL content. (CVE-2015-0830)

Use-after-free vulnerability in the
mozilla::dom::IndexedDB::IDBObjectStore::CreateIndex function in Mozilla
Firefox before 36.0, Firefox ESR 31.x before 31.5, and Thunderbird before
31.5 allows remote attackers to execute arbitrary code or cause a denial of
service (heap memory corruption) via crafted content that is improperly
handled during IndexedDB index creation. (CVE-2015-0831)

Buffer overflow in libstagefright in Mozilla Firefox before 36.0 allows
remote attackers to execute arbitrary code via a crafted MP4 video that is
improperly handled during playback. (CVE-2015-0829)

Double free vulnerability in the nsXMLHttpRequest::GetResponse function in
Mozilla Firefox before 36.0, when a nonstandard memory allocator is used,
allows remote attackers to execute arbitrary code or cause a denial of
service (heap memory corruption) via crafted JavaScript code that makes an
XMLHttpRequest call with zero bytes of data. (CVE-2015-0828)

Heap-based buffer overflow in the mozilla::gfx::CopyRect function in
Mozilla Firefox before 36.0, Firefox ESR 31.x before 31.5, and Thunderbird
before 31.5 allows remote attackers to obtain sensitive information from
uninitialized process memory via a malformed SVG graphic. (CVE-2015-0827)

The nsTransformedTextRun::SetCapitalization function in Mozilla Firefox
before 36.0 allows remote attackers to execute arbitrary code or cause a
denial of service (out-of-bounds read of heap memory) via a crafted
Cascading Style Sheets (CSS) token sequence that triggers a restyle or
reflow operation. (CVE-2015-0826)

Stack-based buffer underflow in the mozilla::MP3FrameParser::ParseBuffer
function in Mozilla Firefox ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.33.1~1.mga4", rls:"MAGEIA4"))) {
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
