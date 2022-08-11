###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3323_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for binutils openSUSE-SU-2018:3323-1 (binutils)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852051");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2017-15938", "CVE-2017-15939", "CVE-2017-15996", "CVE-2017-16826", "CVE-2017-16827", "CVE-2017-16828", "CVE-2017-16829", "CVE-2017-16830", "CVE-2017-16831", "CVE-2017-16832", "CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10534", "CVE-2018-10535", "CVE-2018-6323", "CVE-2018-6543", "CVE-2018-6759", "CVE-2018-6872", "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7570", "CVE-2018-7642", "CVE-2018-7643", "CVE-2018-8945");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:38:06 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for binutils openSUSE-SU-2018:3323-1 (binutils)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00049.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils'
  package(s) announced via the openSUSE-SU-2018:3323_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils to version 2.31 fixes the following issues:

  These security issues were fixed:

  - CVE-2017-15996: readelf allowed remote attackers to cause a denial of
  service (excessive memory allocation) or possibly have unspecified other
  impact via a crafted ELF file that triggered a buffer overflow on fuzzed
  archive header (bsc#1065643)

  - CVE-2017-15939: Binary File Descriptor (BFD) library (aka libbfd)
  mishandled NULL files in a .debug_line file table, which allowed remote
  attackers to cause a denial of service (NULL pointer dereference and
  application crash) via a crafted ELF file, related to concat_filename
  (bsc#1065689)

  - CVE-2017-15938: the Binary File Descriptor (BFD) library (aka libbfd)
  miscalculated DW_FORM_ref_addr die refs in the case of a relocatable
  object file, which allowed remote attackers to cause a denial of service
  (find_abstract_instance_name invalid memory read, segmentation fault,
  and application crash) (bsc#1065693)

  - CVE-2017-16826: The coff_slurp_line_table function the Binary File
  Descriptor (BFD) library (aka libbfd) allowed remote attackers to cause
  a denial of service (invalid memory access and application crash) or
  possibly have unspecified other impact via a crafted PE file
  (bsc#1068640)

  - CVE-2017-16832: The pe_bfd_read_buildid function in the Binary File
  Descriptor (BFD) library (aka libbfd) did not validate size and offset
  values in the data dictionary, which allowed remote attackers to cause a
  denial of service (segmentation violation and application crash) or
  possibly have unspecified other impact via a crafted PE file
  (bsc#1068643)

  - CVE-2017-16831: Binary File Descriptor (BFD) library (aka libbfd) did
  not validate the symbol count, which allowed remote attackers to cause a
  denial of service (integer overflow and application crash, or excessive
  memory allocation) or possibly have unspecified other impact via a
  crafted PE file (bsc#1068887)

  - CVE-2017-16830: The print_gnu_property_note function did not have
  integer-overflow protection on 32-bit platforms, which allowed remote
  attackers to cause a denial of service (segmentation violation and
  application crash) or possibly have unspecified other impact via a
  crafted ELF file (bsc#1068888)

  - CVE-2017-16829: The _bfd_elf_parse_gnu_properties function in the Binary
  File Descriptor (BFD) library (aka libbfd) did not prevent negative
  pointers, which allowed remote attackers to cause a denial of service
  (out-of-bounds read and application crash) or possibly have unspecified
  other impact via a crafted ELF file ( ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"binutils on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-aarch64-binutils", rpm:"cross-aarch64-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-aarch64-binutils-debuginfo", rpm:"cross-aarch64-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-aarch64-binutils-debugsource", rpm:"cross-aarch64-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-arm-binutils", rpm:"cross-arm-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-arm-binutils-debuginfo", rpm:"cross-arm-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-arm-binutils-debugsource", rpm:"cross-arm-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-avr-binutils", rpm:"cross-avr-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-avr-binutils-debuginfo", rpm:"cross-avr-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-avr-binutils-debugsource", rpm:"cross-avr-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-epiphany-binutils", rpm:"cross-epiphany-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-epiphany-binutils-debuginfo", rpm:"cross-epiphany-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-epiphany-binutils-debugsource", rpm:"cross-epiphany-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-hppa-binutils", rpm:"cross-hppa-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-hppa-binutils-debuginfo", rpm:"cross-hppa-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-hppa-binutils-debugsource", rpm:"cross-hppa-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-hppa64-binutils", rpm:"cross-hppa64-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-hppa64-binutils-debuginfo", rpm:"cross-hppa64-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-hppa64-binutils-debugsource", rpm:"cross-hppa64-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-i386-binutils", rpm:"cross-i386-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-i386-binutils-debuginfo", rpm:"cross-i386-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-i386-binutils-debugsource", rpm:"cross-i386-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ia64-binutils", rpm:"cross-ia64-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ia64-binutils-debuginfo", rpm:"cross-ia64-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ia64-binutils-debugsource", rpm:"cross-ia64-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-m68k-binutils", rpm:"cross-m68k-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-m68k-binutils-debuginfo", rpm:"cross-m68k-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-m68k-binutils-debugsource", rpm:"cross-m68k-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-mips-binutils", rpm:"cross-mips-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-mips-binutils-debuginfo", rpm:"cross-mips-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-mips-binutils-debugsource", rpm:"cross-mips-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ppc-binutils", rpm:"cross-ppc-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ppc-binutils-debuginfo", rpm:"cross-ppc-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ppc-binutils-debugsource", rpm:"cross-ppc-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ppc64-binutils", rpm:"cross-ppc64-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ppc64-binutils-debuginfo", rpm:"cross-ppc64-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ppc64-binutils-debugsource", rpm:"cross-ppc64-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ppc64le-binutils", rpm:"cross-ppc64le-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ppc64le-binutils-debuginfo", rpm:"cross-ppc64le-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-ppc64le-binutils-debugsource", rpm:"cross-ppc64le-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-riscv64-binutils", rpm:"cross-riscv64-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-riscv64-binutils-debuginfo", rpm:"cross-riscv64-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-riscv64-binutils-debugsource", rpm:"cross-riscv64-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-rx-binutils", rpm:"cross-rx-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-rx-binutils-debuginfo", rpm:"cross-rx-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-rx-binutils-debugsource", rpm:"cross-rx-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-s390-binutils", rpm:"cross-s390-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-s390-binutils-debuginfo", rpm:"cross-s390-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-s390-binutils-debugsource", rpm:"cross-s390-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-s390x-binutils", rpm:"cross-s390x-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-s390x-binutils-debuginfo", rpm:"cross-s390x-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-s390x-binutils-debugsource", rpm:"cross-s390x-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-sparc-binutils", rpm:"cross-sparc-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-sparc-binutils-debuginfo", rpm:"cross-sparc-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-sparc-binutils-debugsource", rpm:"cross-sparc-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-sparc64-binutils", rpm:"cross-sparc64-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-sparc64-binutils-debuginfo", rpm:"cross-sparc64-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-sparc64-binutils-debugsource", rpm:"cross-sparc64-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-spu-binutils", rpm:"cross-spu-binutils~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-spu-binutils-debuginfo", rpm:"cross-spu-binutils-debuginfo~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cross-spu-binutils-debugsource", rpm:"cross-spu-binutils-debugsource~2.31~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
