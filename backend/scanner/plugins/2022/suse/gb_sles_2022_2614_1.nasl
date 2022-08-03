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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2614.1");
  script_cve_id("CVE-2017-7607", "CVE-2017-7608", "CVE-2017-7609", "CVE-2017-7610", "CVE-2017-7611", "CVE-2017-7612", "CVE-2017-7613", "CVE-2018-16062", "CVE-2018-16402", "CVE-2018-16403", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7146", "CVE-2019-7148", "CVE-2019-7149", "CVE-2019-7150", "CVE-2019-7664", "CVE-2019-7665");
  script_tag(name:"creation_date", value:"2022-08-02 04:46:45 +0000 (Tue, 02 Aug 2022)");
  script_version("2022-08-02T10:11:24+0000");
  script_tag(name:"last_modification", value:"2022-08-02 10:11:24 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 22:13:00 +0000 (Tue, 30 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2614-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2614-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222614-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dwarves and elfutils' package(s) announced via the SUSE-SU-2022:2614-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dwarves and elfutils fixes the following issues:

elfutils was updated to version 0.177 (jsc#SLE-24501):

elfclassify: New tool to analyze ELF objects.

readelf: Print DW_AT_data_member_location as decimal offset. Decode
 DW_AT_discr_list block attributes.

libdw: Add DW_AT_GNU_numerator, DW_AT_GNU_denominator and DW_AT_GNU_bias.

libdwelf: Add dwelf_elf_e_machine_string. dwelf_elf_begin now only
 returns NULL when there is an error reading or decompressing a file. If
 the file is not an ELF file an ELF handle of type ELF_K_NONE is returned.

backends: Add support for C-SKY.

Update to version 0.176:

build: Add new --enable-install-elfh option. Do NOT use this for system
 installs (it overrides glibc elf.h).

backends: riscv improved core file and return value location support.

Fixes:
 - CVE-2019-7146, CVE-2019-7148, CVE-2019-7149, CVE-2019-7664 -
 CVE-2019-7150: dwfl_segment_report_module doesn't check whether the
 dyn data read from core file is truncated (bsc#1123685)
 - CVE-2019-7665: NT_PLATFORM core file note should be a zero terminated
 string (CVE is a bit misleading, as this is not a bug in libelf as
 described) (bsc#1125007)

Update to version 0.175:

readelf: Handle multiple .debug_macro sections. Recognize and parse GNU
 Property, NT_VERSION and GNU Build Attribute ELF Notes.

strip: Handle SHT_GROUP correctly. Add strip --reloc-debug-sections-only
 option. Handle relocations against GNU compressed sections.

libdwelf: New function dwelf_elf_begin.

libcpu: Recognize bpf jump variants BPF_JLT, BPF_JLE, BPF_JSLT and
 BPF_JSLE. backends: RISCV handles ADD/SUB relocations. Handle
 SHT_X86_64_UNWIND.
 - CVE-2018-18521: arlib: Divide-by-zero vulnerabilities in the function
 arlib_add_symbols() used by eu-ranlib (bsc#1112723)
 - CVE-2018-18310: Invalid Address Read problem in
 dwfl_segment_report_module.c (bsc#1111973)
 - CVE-2018-18520: eu-size: Bad handling of ar files inside are files
 (bsc#1112726)

Update to version 0.174:

libelf, libdw and all tools now handle extended shnum and shstrndx
 correctly.

elfcompress: Don't rewrite input file if no section data needs updating.
 Try harder to keep same file mode bits (suid) on rewrite.

strip: Handle mixed (out of order) allocated/non-allocated sections.

unstrip: Handle SHT_GROUP sections.

backends: RISCV and M68K now have backend implementations to generate
 CFI based backtraces.

Fixes:
 - CVE-2018-16402: libelf: denial of service/double free on an attempt to
 decompress the same section twice (bsc#1107066) Double-free crash in
 nm and readelf
 - CVE-2018-16403: heap buffer overflow in readelf (bsc#1107067)
 - CVE-2018-16062: heap-buffer-overflow in
 /elfutils/libdw/dwarf_getaranges.c:156 (bsc#1106390)

Update to version 0.173:

More fixes for crashes and hangs found by afl-fuzz. In particular
 various functions now detect and break infinite loops caused by bad DIE
 tree cycles.

readelf: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dwarves and elfutils' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"dwarves", rpm:"dwarves~1.22~150300.7.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dwarves-debuginfo", rpm:"dwarves-debuginfo~1.22~150300.7.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dwarves-debugsource", rpm:"dwarves-debugsource~1.22~150300.7.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-debuginfo", rpm:"elfutils-debuginfo~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-debugsource", rpm:"elfutils-debugsource~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-lang", rpm:"elfutils-lang~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm-devel", rpm:"libasm-devel~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1", rpm:"libasm1~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1-debuginfo", rpm:"libasm1-debuginfo~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw-devel", rpm:"libdw-devel~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1", rpm:"libdw1~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit", rpm:"libdw1-32bit~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit-debuginfo", rpm:"libdw1-32bit-debuginfo~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-debuginfo", rpm:"libdw1-debuginfo~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarves-devel", rpm:"libdwarves-devel~1.22~150300.7.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarves-devel-32bit", rpm:"libdwarves-devel-32bit~1.22~150300.7.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarves1", rpm:"libdwarves1~1.22~150300.7.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarves1-32bit", rpm:"libdwarves1-32bit~1.22~150300.7.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarves1-32bit-debuginfo", rpm:"libdwarves1-32bit-debuginfo~1.22~150300.7.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarves1-debuginfo", rpm:"libdwarves1-debuginfo~1.22~150300.7.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-devel", rpm:"libebl-devel~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins", rpm:"libebl-plugins~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins-32bit", rpm:"libebl-plugins-32bit~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins-32bit-debuginfo", rpm:"libebl-plugins-32bit-debuginfo~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins-debuginfo", rpm:"libebl-plugins-debuginfo~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf-devel", rpm:"libelf-devel~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1", rpm:"libelf1~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit", rpm:"libelf1-32bit~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit-debuginfo", rpm:"libelf1-32bit-debuginfo~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-debuginfo", rpm:"libelf1-debuginfo~0.177~150300.11.3.1", rls:"SLES15.0SP3"))) {
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
