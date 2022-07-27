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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0294");
  script_cve_id("CVE-2018-12983", "CVE-2018-20751", "CVE-2019-20093", "CVE-2019-9199", "CVE-2019-9687");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0294)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0294");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0294.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24385");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/Y6ZKYPW55PN6XV5XW6KZDIJLWRXON74N/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/5Z7UF3AC76HHLSAHVBUQWMYXHR33DR34/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4K6FST3UH3WNUNCIAEEGZJJASCP5ZXUF/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SSB4HRLHF7H3DPNTFPTXUE6EGXXZ5JSZ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/WR6XY3TOLJPLXOGHYPCB42JW3SWRZNY4/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podofo' package(s) announced via the MGASA-2020-0294 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

A stack-based buffer over-read in the PdfEncryptMD5Base::ComputeEncryptionKey()
function in PdfEncrypt.cpp in PoDoFo 0.9.6-rc1 could be leveraged by remote
attackers to cause a denial-of-service via a crafted pdf file. (CVE-2018-12983)

An issue was discovered in crop_page in PoDoFo 0.9.6. For a crafted PDF document,
pPage->GetObject()->GetDictionary().AddKey(PdfName('MediaBox'),var) can be
problematic due to the function GetObject() being called for the pPage NULL
pointer object. The value of pPage at this point is 0x0, which causes a NULL
pointer dereference. (CVE-2018-20751)

PoDoFo::Impose::PdfTranslator::setSource() in pdftranslator.cpp in PoDoFo 0.9.6
has a NULL pointer dereference that can (for example) be triggered by sending a
crafted PDF file to the podofoimpose binary. It allows an attacker to cause
Denial of Service (Segmentation fault) or possibly have unspecified other impact.
(CVE-2019-9199)

PoDoFo 0.9.6 has a heap-based buffer overflow in PdfString::ConvertUTF16toUTF8 in
base/PdfString.cpp. (CVE-2019-9687)

The PoDoFo::PdfVariant::DelayedLoad function in PdfVariant.h in PoDoFo 0.9.6 allows
remote attackers to cause a denial of service (NULL pointer dereference) via a
crafted file, because of ImageExtractor.cpp. (CVE-2019-20093)");

  script_tag(name:"affected", value:"'podofo' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64podofo-devel", rpm:"lib64podofo-devel~0.9.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64podofo0.9.6", rpm:"lib64podofo0.9.6~0.9.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo-devel", rpm:"libpodofo-devel~0.9.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0.9.6", rpm:"libpodofo0.9.6~0.9.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo", rpm:"podofo~0.9.6~1.1.mga7", rls:"MAGEIA7"))) {
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
