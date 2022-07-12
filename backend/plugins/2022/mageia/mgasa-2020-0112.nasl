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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0112");
  script_cve_id("CVE-2019-1010204", "CVE-2019-14250", "CVE-2019-17450", "CVE-2019-17451");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0112)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0112");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0112.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25298");
  script_xref(name:"URL", value:"https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob_plain;f=binutils/NEWS;hb=refs/tags/binutils-2_33_1");
  script_xref(name:"URL", value:"https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob_plain;f=gas/NEWS;hb=refs/tags/binutils-2_33_1");
  script_xref(name:"URL", value:"https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob_plain;f=ld/NEWS;hb=refs/tags/binutils-2_33_1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the MGASA-2020-0112 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the binutils 2.33.1 and fixes at least the
following security issues:

An issue was discovered in GNU libiberty, as distributed in GNU Binutils
2.32. simple_object_elf_match in simple-object-elf.c does not check for a
zero shstrndx value, leading to an integer overflow and resultant heap-
based buffer overflow (CVE-2019-14250).

find_abstract_instance in dwarf2.c in the Binary File Descriptor (BFD)
library (aka libbfd), as distributed in GNU Binutils 2.32, allows remote
attackers to cause a denial of service (infinite recursion and application
crash) via a crafted ELF file )CVE-2019-17450).

An issue was discovered in the Binary File Descriptor (BFD) library (aka
libbfd), as distributed in GNU Binutils 2.32. It is an integer overflow
leading to a SEGV in _bfd_dwarf2_find_nearest_line in dwarf2.c, as
demonstrated by nm (CVE-2019-17451).

GNU binutils gold linker is affected by Improper Input Validation, Signed/
Unsigned Comparison, Out-of-bounds Read. The impact is: Denial of service.
The attack vector is: An ELF file with an invalid e_shoff header field
must be opened (CVE-2019-1010204).

For more information about the other changes and additional features of
binutils / gas / ld in this update, see the referenced sourceware.org
NEWS links.");

  script_tag(name:"affected", value:"'binutils' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.33.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64binutils-devel", rpm:"lib64binutils-devel~2.33.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbinutils-devel", rpm:"libbinutils-devel~2.33.1~1.mga7", rls:"MAGEIA7"))) {
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
