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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0239");
  script_cve_id("CVE-2017-18233", "CVE-2017-18234", "CVE-2017-18235", "CVE-2017-18236", "CVE-2017-18237", "CVE-2018-7729", "CVE-2018-7731");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0239)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0239");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0239.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22871");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/ZTR7ZDRVKLKSI65QBRMJFDTW4EPRPZYH/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/H4PKNNGR3XYNB7B7BYNWTABCOPERDDLB/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exempi' package(s) announced via the MGASA-2018-0239 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Exempi through 2.4.4. There is a stack-based
buffer over-read in the PostScript_MetaHandler::ParsePSFile() function
in PostScript_Handler.cpp (CVE-2018-7729).

An issue was discovered in Exempi through 2.4.4. WEBP_Support.cpp does
not check whether a bitstream has a NULL value, leading to a NULL
pointer dereference in the WEBP::VP8XChunk class (CVE-2018-7731).

An issue was discovered in Exempi before 2.4.4. Integer overflow in the
Chunk class in RIFF.cpp allows remote attackers to cause a denial of
service (infinite loop) via crafted XMP data in a .avi file
(CVE-2017-18233).

An issue was discovered in Exempi before 2.4.3. It allows remote
attackers to cause a denial of service (invalid memcpy with resultant
use-after-free) or possibly have unspecified other impact via a .pdf
file containing JPEG data, related to ReconcileTIFF.cpp,
TIFF_MemoryReader.cpp, and TIFF_Support.hpp (CVE-2017-18234).

An issue was discovered in Exempi before 2.4.3. The VPXChunk class in
WEBP_Support.cpp does not ensure nonzero widths and heights, which
allows remote attackers to cause a denial of service (assertion failure
and application exit) via a crafted .webp file (CVE-2017-18235).

An issue was discovered in Exempi before 2.4.4. The
ASF_Support::ReadHeaderObject function in ASF_Support.cpp allows remote
attackers to cause a denial of service (infinite loop) via a crafted
.asf file (CVE-2017-18236).

An issue was discovered in Exempi before 2.4.3. The
PostScript_Support::ConvertToDate function in PostScript_Support.cpp
allows remote attackers to cause a denial of service (invalid pointer
dereference and application crash) via a crafted .ps file
(CVE-2017-18237).");

  script_tag(name:"affected", value:"'exempi' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"exempi", rpm:"exempi~2.4.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exempi-devel", rpm:"lib64exempi-devel~2.4.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exempi3", rpm:"lib64exempi3~2.4.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexempi-devel", rpm:"libexempi-devel~2.4.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexempi3", rpm:"libexempi3~2.4.5~1.mga6", rls:"MAGEIA6"))) {
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
