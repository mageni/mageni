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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4146.1");
  script_cve_id("CVE-2019-1010204", "CVE-2021-3530", "CVE-2021-3648", "CVE-2021-3826", "CVE-2021-45078", "CVE-2021-46195", "CVE-2022-27943", "CVE-2022-38126", "CVE-2022-38127", "CVE-2022-38533");
  script_tag(name:"creation_date", value:"2022-11-22 04:21:37 +0000 (Tue, 22 Nov 2022)");
  script_version("2022-11-22T10:12:16+0000");
  script_tag(name:"last_modification", value:"2022-11-22 10:12:16 +0000 (Tue, 22 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-21 17:29:00 +0000 (Tue, 21 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4146-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4146-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224146-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the SUSE-SU-2022:4146-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils fixes the following issues:

The following security bugs were fixed:

CVE-2019-1010204: Fixed out-of-bounds read in elfcpp/elfcpp_file.h
 (bsc#1142579).

CVE-2021-3530: Fixed stack-based buffer overflow in demangle_path() in
 rust-demangle.c (bsc#1185597).

CVE-2021-3648: Fixed infinite loop while demangling rust symbols
 (bsc#1188374).

CVE-2021-3826: Fixed heap/stack buffer overflow in the dlang_lname
 function in d-demangle.c (bsc#1202969).

CVE-2021-45078: Fixed out-of-bounds write in stab_xcoff_builtin_type()
 in stabs.c (bsc#1193929).

CVE-2021-46195: Fixed uncontrolled recursion in
 libiberty/rust-demangle.c (bsc#1194783).

CVE-2022-27943: Fixed stack exhaustion in demangle_const in
 (bsc#1197592).

CVE-2022-38126: Fixed assertion fail in the display_debug_names()
 function in binutils/dwarf.c (bsc#1202966).

CVE-2022-38127: Fixed NULL pointer dereference in the
 read_and_display_attr_value() function in binutils/dwarf.c (bsc#1202967).

CVE-2022-38533: Fixed heap out-of-bounds read in bfd_getl32
 (bsc#1202816).


The following non-security bugs were fixed:

SLE toolchain update of binutils, update to 2.39 from 2.37.

Update to 2.39:
 * The ELF linker will now generate a warning message if the stack is
 made executable. Similarly it will warn if the output binary contains
 a segment with all three of the read, write and execute permission
 bits set. These warnings are intended to help developers identify
 programs which might be vulnerable to attack via these executable
 memory regions. The warnings are enabled by default but can be
 disabled via a command line option. It is also possible to build a
 linker with the warnings disabled, should that be necessary.
 * The ELF linker now supports a --package-metadata option that allows
 embedding a JSON payload in accordance to the Package Metadata
 specification.
 * In linker scripts it is now possible to use TYPE= in an output
 section description to set the section type value.
 * The objdump program now supports coloured/colored syntax highlighting
 of its disassembler output for some architectures. (Currently: AVR,
 RiscV, s390, x86, x86_64).
 * The nm program now supports a --no-weak/-W option to make it ignore
 weak symbols.
 * The readelf and objdump programs now support a -wE option to prevent
 them from attempting to access debuginfod servers when following links.
 * The objcopy program's --weaken, --weaken-symbol, and
 --weaken-symbols options now works with unique symbols as well.

Update to 2.38:
 * elfedit: Add --output-abiversion option to update ABIVERSION.
 * Add support for the LoongArch instruction set.
 * Tools which display symbols or strings (readelf, strings, nm, objdump)
 have a new command line option which controls how unicode characters
 are handled. By default they are treated as normal for the tool.
 Using
 --unicode=locale will display them according to the current ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.39~150100.7.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.39~150100.7.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.39~150100.7.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.39~150100.7.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.39~150100.7.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.39~150100.7.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.39~150100.7.40.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.39~150100.7.40.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.39~150100.7.40.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.39~150100.7.40.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.39~150100.7.40.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.39~150100.7.40.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.39~150100.7.40.1", rls:"SLES15.0SP2"))) {
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
