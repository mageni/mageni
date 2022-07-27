# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2558");
  script_version("2020-01-23T13:05:39+0000");
  script_cve_id("CVE-2014-9939", "CVE-2017-12452", "CVE-2017-12453", "CVE-2017-12454", "CVE-2017-12456", "CVE-2017-12967", "CVE-2017-13710", "CVE-2017-14128", "CVE-2017-14129", "CVE-2017-14529", "CVE-2017-14930", "CVE-2017-14932", "CVE-2017-14934", "CVE-2017-14938", "CVE-2017-14939", "CVE-2017-14940", "CVE-2017-15021", "CVE-2017-15022", "CVE-2017-15024", "CVE-2017-15025", "CVE-2017-15225", "CVE-2017-15938", "CVE-2017-17080", "CVE-2017-17121", "CVE-2017-17122", "CVE-2017-17123", "CVE-2017-17124", "CVE-2017-6969", "CVE-2017-7210", "CVE-2017-7223", "CVE-2017-7224", "CVE-2017-7225", "CVE-2017-7226", "CVE-2017-7227", "CVE-2017-7299", "CVE-2017-7300", "CVE-2017-7301", "CVE-2017-7614", "CVE-2017-8394", "CVE-2017-8395", "CVE-2017-8421", "CVE-2017-9038", "CVE-2017-9039", "CVE-2017-9041", "CVE-2017-9745", "CVE-2017-9750", "CVE-2017-9751", "CVE-2017-9755", "CVE-2017-9954", "CVE-2018-14038", "CVE-2018-18605", "CVE-2018-18606", "CVE-2018-18607", "CVE-2018-20002", "CVE-2018-6323", "CVE-2018-6759", "CVE-2018-9138", "CVE-2019-9074");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 13:05:39 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 13:05:39 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for binutils (EulerOS-SA-2019-2558)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2558");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'binutils' package(s) announced via the EulerOS-SA-2019-2558 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The aout_32_swap_std_reloc_out function in aoutx.h in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils before 2.31, allows remote attackers to cause a denial of service (segmentation fault and application crash) via a crafted file, as demonstrated by objcopy.(CVE-2018-14038)

_bfd_dwarf2_cleanup_debug_info in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (memory leak) via a crafted ELF file.(CVE-2017-15225)

_bfd_elf_slurp_version_tables in elf.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (excessive memory allocation and application crash) via a crafted ELF file.(CVE-2017-14938)

A heap-based buffer over-read issue was discovered in the function sec_merge_hash_lookup in merge.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31, because _bfd_add_merge_section mishandles section merges when size is not a multiple of entsize. A specially crafted ELF allows remote attackers to cause a denial of service, as demonstrated by ld.(CVE-2018-18605)

An issue was discovered in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.29 and 2.30. Stack Exhaustion occurs in the C++ demangling functions provided by libiberty, and there are recursive stack frames: demangle_nested_args, demangle_args, do_arg, and do_type.(CVE-2018-9138)

An issue was discovered in elf_link_input_bfd in elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31. There is a NULL pointer dereference in elf_link_input_bfd when used for finding STT_TLS symbols without any TLS section. A specially crafted ELF allows remote attackers to cause a denial of service, as demonstrated by ld.(CVE-2018-18607)

An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.32. It is an out-of-bounds read leading to a SEGV in bfd_getl32 in libbfd.c, when called from pex64_get_runtime_function in pei-x86_64.c.(CVE-2019-9074)

An issue was discovered in the merge_strings function in merge.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31. There is a NULL pointer dereference in _bfd_add_merge_section when attempting to merge sections with large alignments. A specially crafted ELF allows remote attackers to cause a denial of service, as demonstrated by ld.(CVE-2018-18606)

bfd_get_debug_link_info_1 in opn ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'binutils' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.25.1~22.base.h33", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.25.1~22.base.h33", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);