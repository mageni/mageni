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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0020");
  script_cve_id("CVE-2018-11468", "CVE-2018-11503", "CVE-2018-11504", "CVE-2018-12495");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-31T07:41:30+0000");
  script_tag(name:"last_modification", value:"2022-01-31 07:41:30 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0020)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0020");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0020.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23540");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/7RPEBFDVJJU7ZJ2OQIKR35QQENJC2EI3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'discount' package(s) announced via the MGASA-2019-0020 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The __mkd_trim_line function in mkdio.c in libmarkdown.a in DISCOUNT
2.2.3a allows remote attackers to cause a denial of service (heap-based
buffer over-read) via a crafted file (CVE-2018-11468).

DISCOUNT through version 2.2.3a is vulnerable to a Heap-based
buffer-overflow in the markdown.c:isfootnote() function. An attacker
could exploit this to cause a denial of service (CVE-2018-11503).

DISCOUNT through version 2.2.3a is vulnerable to a Heap-based
buffer-overflow in the markdown.c:islist() function. An attacker
could exploit this to cause a denial of service (CVE-2018-11504).

The quoteblock function in markdown.c in libmarkdown.a in DISCOUNT
2.2.3a allows remote attackers to cause a denial of service
(heap-based buffer over-read) via a crafted file (CVE-2018-12495).");

  script_tag(name:"affected", value:"'discount' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"discount", rpm:"discount~2.2.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64markdown-devel", rpm:"lib64markdown-devel~2.2.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64markdown2", rpm:"lib64markdown2~2.2.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmarkdown-devel", rpm:"libmarkdown-devel~2.2.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmarkdown2", rpm:"libmarkdown2~2.2.4~1.mga6", rls:"MAGEIA6"))) {
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
