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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0129");
  script_cve_id("CVE-2017-17810", "CVE-2017-17811", "CVE-2017-17812", "CVE-2017-17813", "CVE-2017-17814", "CVE-2017-17815", "CVE-2017-17816", "CVE-2017-17817", "CVE-2017-17818", "CVE-2017-17819", "CVE-2017-17820");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0129)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0129");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0129.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22388");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nasm' package(s) announced via the MGASA-2018-0129 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides nasm 2.13.03 and fixes the following security issues:

In Netwide Assembler (NASM) 2.14rc0, there is a 'SEGV on unknown address'
that will cause a remote denial of service attack, because asm/preproc.c
mishandles macro calls that have the wrong number of arguments.

In Netwide Assembler (NASM) 2.14rc0, there is a heap-based buffer overflow
that will cause a remote denial of service attack, related to a strcpy in
paste_tokens in asm/preproc.c, a similar issue to CVE-2017-11111.

In Netwide Assembler (NASM) 2.14rc0, there is a heap-based buffer over-read
in the function detoken() in asm/preproc.c that will cause a remote denial
of service attack.

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in the
pp_list_one_macro function in asm/preproc.c that will cause a remote denial
of service attack, related to mishandling of line-syntax errors.

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in
do_directive in asm/preproc.c that will cause a remote denial of service
attack.

In Netwide Assembler (NASM) 2.14rc0, there is an illegal address access in
is_mmacro() in asm/preproc.c that will cause a remote denial of service
attack, because of a missing check for the relationship between minimum
and maximum parameter counts.

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in
pp_getline in asm/preproc.c that will cause a remote denial of service
attack.

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in
pp_verror in asm/preproc.c that will cause a remote denial of service
attack.

In Netwide Assembler (NASM) 2.14rc0, there is a heap-based buffer over-read
that will cause a remote denial of service attack, related to a while loop
in paste_tokens in asm/preproc.c.

In Netwide Assembler (NASM) 2.14rc0, there is an illegal address access in
the function find_cc() in asm/preproc.c that will cause a remote denial of
service attack, because pointers associated with skip_white_ calls are not
validated.

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in
pp_list_one_macro in asm/preproc.c that will lead to a remote denial of
service attack, related to mishandling of operand-type errors.");

  script_tag(name:"affected", value:"'nasm' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"nasm", rpm:"nasm~2.13.03~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-doc", rpm:"nasm-doc~2.13.03~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-rdoff", rpm:"nasm-rdoff~2.13.03~1.mga6", rls:"MAGEIA6"))) {
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
