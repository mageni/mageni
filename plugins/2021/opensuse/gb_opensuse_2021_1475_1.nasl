# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854301");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2020-16590", "CVE-2020-16591", "CVE-2020-16592", "CVE-2020-16593", "CVE-2020-16598", "CVE-2020-16599", "CVE-2020-35448", "CVE-2020-35493", "CVE-2020-35496", "CVE-2020-35507", "CVE-2021-20197", "CVE-2021-20284", "CVE-2021-20294", "CVE-2021-3487");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-16 02:02:22 +0000 (Tue, 16 Nov 2021)");
  script_name("openSUSE: Security Advisory for binutils (openSUSE-SU-2021:1475-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1475-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/N6RYWEZ5BKTK6UEP6HAB7B466BPC3SMJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils'
  package(s) announced via the openSUSE-SU-2021:1475-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils fixes the following issues:

     Update to binutils 2.37:

  * The GNU Binutils sources now requires a C99 compiler and library to
       build.

  * Support for Realm Management Extension (RME) for AArch64 has been added.

  * A new linker option &#x27 -z report-relative-reloc&#x27  for x86 ELF targets has
       been added to report dynamic relative relocations.

  * A new linker option &#x27 -z start-stop-gc&#x27  has been added to disable special
       treatment of __start_*/__stop_* references when

  - -gc-sections.

  * A new linker options &#x27 -Bno-symbolic&#x27  has been added which will cancel
       the &#x27 -Bsymbolic&#x27  and &#x27 -Bsymbolic-functions&#x27  options.

  * The readelf tool has a new command line option which can be used to
       specify how the numeric values of symbols are reported.

  - -sym-base=081016 tells readelf to display the values in base 8, base
        10 or base 16.  A sym base of 0 represents the default action
       of displaying values under 10000 in base 10 and values above that in
        base 16.

  * A new format has been added to the nm program.  Specifying
       &#x27 --format=just-symbols&#x27  (or just using -j) will tell the program to
       only display symbol names and nothing else.

  * A new command line option &#x27 --keep-section-symbols&#x27  has been added to
       objcopy and strip.  This stops the removal of unused section symbols
        when the file is copied.  Removing these symbols saves space, but
        sometimes they are needed by other tools.

  * The &#x27 --weaken&#x27, &#x27 --weaken-symbol&#x27  and
  &#x27 --weaken-symbols&#x27  options
       supported by objcopy now make undefined symbols weak on targets that
       support weak symbols.

  * Readelf and objdump can now display and use the contents of .debug_sup
       sections.

  * Readelf and objdump will now follow links to separate debug info files
       by default.  This behaviour can be stopped via the use of the new &#x27 -wN&#x27
       or &#x27 --debug-dump=no-follow-links&#x27  options for readelf and the
  &#x27 -WN&#x27  or
       &#x27 --dwarf=no-follow-links&#x27  options for objdump.  Also the old behaviour
       can be restored by the use of the &#x27 --enable-follow-debug-links=no&#x27
       configure time option.

       The semantics of the =follow-links option have also been slightly
     changed.  When enabled, the option allows for the loading of symbol tables
     and string tables from the separate files which can be used to enhance the
     information displ ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'binutils' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bpftrace-tools", rpm:"bpftrace-tools~0.11.4~lp152.2.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bpftrace", rpm:"bpftrace~0.11.4~lp152.2.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils", rpm:"cross-aarch64-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debuginfo", rpm:"cross-aarch64-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debugsource", rpm:"cross-aarch64-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils", rpm:"cross-arm-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debuginfo", rpm:"cross-arm-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debugsource", rpm:"cross-arm-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils", rpm:"cross-avr-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debuginfo", rpm:"cross-avr-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debugsource", rpm:"cross-avr-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils", rpm:"cross-epiphany-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debuginfo", rpm:"cross-epiphany-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debugsource", rpm:"cross-epiphany-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils", rpm:"cross-hppa-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debuginfo", rpm:"cross-hppa-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debugsource", rpm:"cross-hppa-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils", rpm:"cross-hppa64-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debuginfo", rpm:"cross-hppa64-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debugsource", rpm:"cross-hppa64-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils", rpm:"cross-i386-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debuginfo", rpm:"cross-i386-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debugsource", rpm:"cross-i386-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils", rpm:"cross-ia64-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debuginfo", rpm:"cross-ia64-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debugsource", rpm:"cross-ia64-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils", rpm:"cross-m68k-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debuginfo", rpm:"cross-m68k-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debugsource", rpm:"cross-m68k-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils", rpm:"cross-mips-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debuginfo", rpm:"cross-mips-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debugsource", rpm:"cross-mips-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils", rpm:"cross-ppc-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debuginfo", rpm:"cross-ppc-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debugsource", rpm:"cross-ppc-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils", rpm:"cross-ppc64-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debuginfo", rpm:"cross-ppc64-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debugsource", rpm:"cross-ppc64-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils", rpm:"cross-ppc64le-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debuginfo", rpm:"cross-ppc64le-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debugsource", rpm:"cross-ppc64le-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils", rpm:"cross-riscv64-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debuginfo", rpm:"cross-riscv64-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debugsource", rpm:"cross-riscv64-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils", rpm:"cross-rx-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debuginfo", rpm:"cross-rx-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debugsource", rpm:"cross-rx-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils", rpm:"cross-s390-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debuginfo", rpm:"cross-s390-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debugsource", rpm:"cross-s390-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils", rpm:"cross-s390x-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debuginfo", rpm:"cross-s390x-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debugsource", rpm:"cross-s390x-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils", rpm:"cross-sparc-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debuginfo", rpm:"cross-sparc-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debugsource", rpm:"cross-sparc-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils", rpm:"cross-sparc64-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debuginfo", rpm:"cross-sparc64-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debugsource", rpm:"cross-sparc64-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils", rpm:"cross-spu-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debuginfo", rpm:"cross-spu-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debugsource", rpm:"cross-spu-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-xtensa-binutils", rpm:"cross-xtensa-binutils~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-xtensa-binutils-debuginfo", rpm:"cross-xtensa-binutils-debuginfo~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-xtensa-binutils-debugsource", rpm:"cross-xtensa-binutils-debugsource~2.37~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
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