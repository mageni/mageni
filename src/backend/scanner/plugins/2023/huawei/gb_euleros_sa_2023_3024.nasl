# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3024");
  script_cve_id("CVE-2021-32256", "CVE-2021-46174", "CVE-2022-27943", "CVE-2022-44840", "CVE-2022-47007", "CVE-2022-47008", "CVE-2022-47010", "CVE-2022-47011", "CVE-2022-47673", "CVE-2022-47695", "CVE-2022-47696", "CVE-2022-48063", "CVE-2022-48064", "CVE-2022-48065");
  script_tag(name:"creation_date", value:"2023-10-31 04:19:09 +0000 (Tue, 31 Oct 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-26 02:15:04 +0000 (Sat, 26 Aug 2023)");

  script_name("Huawei EulerOS: Security Advisory for binutils (EulerOS-SA-2023-3024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=(EULEROS\-2\.0SP11\-X86_64|EULEROSVIRT\-2\.9\.1)");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3024");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3024");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'binutils' package(s) announced via the EulerOS-SA-2023-3024 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.(CVE-2022-27943)

An issue was discovered in GNU libiberty, as distributed in GNU Binutils 2.36. It is a stack-overflow issue in demangle_type in rust-demangle.c.(CVE-2021-32256)

An issue was discovered Binutils objdump before 2.39.3 allows attackers to cause a denial of service or other unspecified impacts via function compare_symbols.(CVE-2022-47696)

An issue was discovered Binutils objdump before 2.39.3 allows attackers to cause a denial of service or other unspecified impacts via function bfd_mach_o_get_synthetic_symtab in match-o.c.(CVE-2022-47695)

An issue was discovered in Binutils addr2line before 2.39.3, function parse_module contains multiple out of bound reads which may cause a denial of service or other unspecified impacts.(CVE-2022-47673)

Heap-based Buffer Overflow in function bfd_getl32 in Binutils objdump 3.37.(CVE-2021-46174)

An issue was discovered function parse_stab_struct_fields in stabs.c in Binutils 2.34 thru 2.38, allows attackers to cause a denial of service due to memory leaks.(CVE-2022-47011)

Heap buffer overflow vulnerability in binutils readelf before 2.40 via function find_section_in_set in file readelf.c.(CVE-2022-44840)

An issue was discovered function make_tempdir, and make_tempname in bucomm.c in Binutils 2.34 thru 2.38, allows attackers to cause a denial of service due to memory leaks.(CVE-2022-47008)

An issue was discovered function pr_function_type in prdbg.c in Binutils 2.34 thru 2.38, allows attackers to cause a denial of service due to memory leaks.(CVE-2022-47010)

An issue was discovered function stab_demangle_v3_arg in stabs.c in Binutils 2.34 thru 2.38, allows attackers to cause a denial of service due to memory leaks.(CVE-2022-47007)

GNU Binutils before 2.40 was discovered to contain a memory leak vulnerability var the function find_abstract_instance in dwarf2.c.(CVE-2022-48065)

GNU Binutils before 2.40 was discovered to contain an excessive memory consumption vulnerability via the function bfd_dwarf2_find_nearest_line_with_alt at dwarf2.c. The attacker could supply a crafted ELF file and cause a DNS attack.(CVE-2022-48064)

GNU Binutils before 2.40 was discovered to contain an excessive memory consumption vulnerability via the function load_separate_debug_files at dwarf2.c. The attacker could supply a crafted ELF file and cause a DNS attack.(CVE-2022-48063)");

  script_tag(name:"affected", value:"'binutils' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.37~6.h25.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.28.0~434.h11.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.28.0~434.h11.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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
