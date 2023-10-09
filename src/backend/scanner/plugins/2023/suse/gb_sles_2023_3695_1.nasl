# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3695.1");
  script_cve_id("CVE-2020-19726", "CVE-2021-32256", "CVE-2022-35205", "CVE-2022-35206", "CVE-2022-4285", "CVE-2022-44840", "CVE-2022-45703", "CVE-2022-47673", "CVE-2022-47695", "CVE-2022-47696", "CVE-2022-48063", "CVE-2022-48064", "CVE-2022-48065", "CVE-2023-0687", "CVE-2023-1579", "CVE-2023-1972", "CVE-2023-2222", "CVE-2023-25585", "CVE-2023-25587", "CVE-2023-25588");
  script_tag(name:"creation_date", value:"2023-09-21 04:21:12 +0000 (Thu, 21 Sep 2023)");
  script_version("2023-09-21T05:05:45+0000");
  script_tag(name:"last_modification", value:"2023-09-21 05:05:45 +0000 (Thu, 21 Sep 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 18:52:00 +0000 (Tue, 14 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3695-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3695-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233695-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the SUSE-SU-2023:3695-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils fixes the following issues:
Update to version 2.41 [jsc#PED-5778]:

The MIPS port now supports the Sony Interactive Entertainment Allegrex
 processor, used with the PlayStation Portable, which implements the MIPS
 II ISA along with a single-precision FPU and a few implementation-specific
 integer instructions.
Objdump's --private option can now be used on PE format files to display the
 fields in the file header and section headers.
New versioned release of libsframe: libsframe.so.1. This release introduces
 versioned symbols with version node name LIBSFRAME_1.0. This release also
 updates the ABI in an incompatible way: this includes removal of
 sframe_get_funcdesc_with_addr API, change in the behavior of
 sframe_fre_get_ra_offset and sframe_fre_get_fp_offset APIs.
SFrame Version 2 is now the default (and only) format version supported by
 gas, ld, readelf and objdump.
Add command-line option, --strip-section-headers, to objcopy and strip to
 remove ELF section header from ELF file.

The RISC-V port now supports the following new standard extensions:


Zicond (conditional zero instructions)

Zfa (additional floating-point instructions)

Zvbb, Zvbc, Zvkg, Zvkned, Zvknh[ab], Zvksed, Zvksh, Zvkn, Zvknc, Zvkng,
 Zvks, Zvksc, Zvkg, Zvkt (vector crypto instructions)


The RISC-V port now supports the following vendor-defined extensions:


XVentanaCondOps


Add support for Intel FRED, LKGS and AMX-COMPLEX instructions.

A new .insn directive is recognized by x86 gas.
Add SME2 support to the AArch64 port.
The linker now accepts a command line option of --remap-inputs
 <PATTERN>=<FILE> to relace any input file that matches <PATTERN> with
 <FILE>. In addition the option --remap-inputs-file=<FILE> can be used to
 specify a file containing any number of these remapping directives.
The linker command line option --print-map-locals can be used to include
 local symbols in a linker map. (ELF targets only).
For most ELF based targets, if the --enable-linker-version option is used
 then the version of the linker will be inserted as a string into the .comment
 section.
The linker script syntax has a new command for output sections: ASCIZ 'string'
 This will insert a zero-terminated string at the current location.

Add command-line option, -z nosectionheader, to omit ELF section
 header.


Contains fixes for these non-CVEs (not security bugs per upstreams SECURITY.md):


bsc#1209642 aka CVE-2023-1579 aka PR29988

bsc#1210297 aka CVE-2023-1972 aka PR30285 bsc#1210733 aka CVE-2023-2222 aka PR29936 bsc#1213458 aka CVE-2021-32256 aka PR105039 (gcc)
bsc#1214565 aka CVE-2020-19726 aka PR26240 bsc#1214567 aka CVE-2022-35206 aka PR29290 bsc#1214579 aka CVE-2022-35205 aka PR29289 bsc#1214580 aka CVE-2022-44840 aka PR29732 bsc#1214604 aka CVE-2022-45703 aka PR29799 bsc#1214611 aka CVE-2022-48065 aka PR29925 bsc#1214619 aka CVE-2022-48064 aka PR29922 bsc#1214620 aka ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.41~9.53.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.41~9.53.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.41~9.53.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.41~9.53.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.41~9.53.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.41~9.53.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.41~9.53.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.41~9.53.1", rls:"SLES12.0SP5"))) {
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
