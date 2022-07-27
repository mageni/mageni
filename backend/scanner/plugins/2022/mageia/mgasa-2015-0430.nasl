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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0430");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2015-0430)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0430");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0430.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17004");
  script_xref(name:"URL", value:"http://talosintel.com/vulnerability-reports/");
  script_xref(name:"URL", value:"http://lists.matroska.org/pipermail/matroska-users/2015-October/006981.html");
  script_xref(name:"URL", value:"http://lists.matroska.org/pipermail/matroska-users/2015-October/006985.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libebml, libmatroska' package(s) announced via the MGASA-2015-0430 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In EbmlMaster::Read() in libebml before 1.3.3, when the parser encountered
a deeply nested element with an infinite size then a following element of
an upper level was not propagated correctly. Instead the element with the
infinite size was added into the EBML element tree a second time resulting
in memory access after freeing it and multiple attempts to free the same
memory address during destruction (TALOS-CAN-0037).

In EbmlUnicodeString::UpdateFromUTF8() in libebml before 1.3.3, when
reading from a UTF-8 string in which the length indicated by a UTF-8
character's first byte exceeds the string's actual number of bytes the
parser would access beyond the end of the string resulting in a heap
information leak (TALOS-CAN-0036).

The libebml package has been updated to version 1.3.3, which fixes these
issues and other bugs, including another invalid memory access issue.

The libmatroska package has also been rebuilt against the updated libebml
and updated to version 1.4.4, which also fixes an invalid memory access
issue and other bugs. See the release announcements for details.");

  script_tag(name:"affected", value:"'libebml, libmatroska' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ebml-devel", rpm:"lib64ebml-devel~1.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ebml4", rpm:"lib64ebml4~1.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64matroska-devel", rpm:"lib64matroska-devel~1.4.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64matroska6", rpm:"lib64matroska6~1.4.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebml", rpm:"libebml~1.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebml-devel", rpm:"libebml-devel~1.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebml4", rpm:"libebml4~1.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmatroska", rpm:"libmatroska~1.4.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmatroska-devel", rpm:"libmatroska-devel~1.4.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmatroska6", rpm:"libmatroska6~1.4.4~1.mga5", rls:"MAGEIA5"))) {
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
