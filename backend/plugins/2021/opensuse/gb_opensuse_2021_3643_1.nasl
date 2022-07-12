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
  script_oid("1.3.6.1.4.1.25623.1.0.854292");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2021-20294");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-10 02:03:47 +0000 (Wed, 10 Nov 2021)");
  script_name("openSUSE: Security Advisory for binutils (openSUSE-SU-2021:3643-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3643-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/O6GNK27D6NPRSWPQWFJADKDTOHPOGY6C");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils'
  package(s) announced via the openSUSE-SU-2021:3643-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils fixes the following issues:

  - For compatibility on old code stream that expect &#x27 brcl 0, label&#x27  to not
       be disassembled as &#x27 jgnop label&#x27  on s390x.  (bsc#1192267) This reverts
       IBM zSeries HLASM support for now.

  - Fixed that ppc64 optflags did not enable LTO (bsc#1188941).

  - Fix empty man-pages from broken release tarball

  - Fixed a memory corruption with rpath option (bsc#1191473).

  - Fixed slow performance of stripping some binaries (bsc#1183909).

     Security issue fixed:

  - CVE-2021-20294: Fixed out-of-bounds write in print_dynamic_symbol in
       readelf (bnc#1184519)");

  script_tag(name:"affected", value:"'binutils' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils", rpm:"cross-arm-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debuginfo", rpm:"cross-arm-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debugsource", rpm:"cross-arm-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils", rpm:"cross-avr-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debuginfo", rpm:"cross-avr-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debugsource", rpm:"cross-avr-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils", rpm:"cross-epiphany-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debuginfo", rpm:"cross-epiphany-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debugsource", rpm:"cross-epiphany-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils", rpm:"cross-hppa-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debuginfo", rpm:"cross-hppa-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debugsource", rpm:"cross-hppa-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils", rpm:"cross-hppa64-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debuginfo", rpm:"cross-hppa64-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debugsource", rpm:"cross-hppa64-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils", rpm:"cross-i386-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debuginfo", rpm:"cross-i386-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debugsource", rpm:"cross-i386-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils", rpm:"cross-ia64-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debuginfo", rpm:"cross-ia64-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debugsource", rpm:"cross-ia64-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils", rpm:"cross-m68k-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debuginfo", rpm:"cross-m68k-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debugsource", rpm:"cross-m68k-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils", rpm:"cross-mips-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debuginfo", rpm:"cross-mips-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debugsource", rpm:"cross-mips-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils", rpm:"cross-ppc-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debuginfo", rpm:"cross-ppc-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debugsource", rpm:"cross-ppc-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils", rpm:"cross-ppc64-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debuginfo", rpm:"cross-ppc64-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debugsource", rpm:"cross-ppc64-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils", rpm:"cross-riscv64-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debuginfo", rpm:"cross-riscv64-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debugsource", rpm:"cross-riscv64-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils", rpm:"cross-rx-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debuginfo", rpm:"cross-rx-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debugsource", rpm:"cross-rx-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils", rpm:"cross-s390-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debuginfo", rpm:"cross-s390-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debugsource", rpm:"cross-s390-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils", rpm:"cross-sparc-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debuginfo", rpm:"cross-sparc-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debugsource", rpm:"cross-sparc-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils", rpm:"cross-sparc64-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debuginfo", rpm:"cross-sparc64-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debugsource", rpm:"cross-sparc64-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils", rpm:"cross-spu-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debuginfo", rpm:"cross-spu-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debugsource", rpm:"cross-spu-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils", rpm:"cross-s390x-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debuginfo", rpm:"cross-s390x-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debugsource", rpm:"cross-s390x-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-x86_64-binutils", rpm:"cross-x86_64-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-x86_64-binutils-debuginfo", rpm:"cross-x86_64-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-x86_64-binutils-debugsource", rpm:"cross-x86_64-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils", rpm:"cross-ppc64le-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debuginfo", rpm:"cross-ppc64le-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debugsource", rpm:"cross-ppc64le-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils", rpm:"cross-aarch64-binutils~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debuginfo", rpm:"cross-aarch64-binutils-debuginfo~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debugsource", rpm:"cross-aarch64-binutils-debugsource~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.37~7.26.1", rls:"openSUSELeap15.3"))) {
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