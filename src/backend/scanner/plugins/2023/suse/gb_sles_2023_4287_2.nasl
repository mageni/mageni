# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4287.2");
  script_cve_id("CVE-2023-4039");
  script_tag(name:"creation_date", value:"2023-11-03 04:20:59 +0000 (Fri, 03 Nov 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 20:01:22 +0000 (Thu, 14 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4287-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4287-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234287-2/");
  script_xref(name:"URL", value:"https://gcc.gnu.org/gcc-13/changes.html");
  script_xref(name:"URL", value:"https://gcc.gnu.org/wiki/BPFBackEnd");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc13' package(s) announced via the SUSE-SU-2023:4287-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc13 fixes the following issues:
NOTE: This update was retracted as it caused breakage with third party applications.
This update ship the GCC 13.2 compiler suite and its base libraries.
The compiler base libraries are provided for all SUSE Linux Enterprise 15 versions and replace the same named GCC 12 ones.
The new compilers for C, C++, and Fortran are provided for SUSE Linux Enterprise 15 SP4 and SP5, and provided in the 'Development Tools' module.
The Go, D, Ada and Modula 2 language compiler parts are available unsupported via the PackageHub repositories.
To use gcc13 compilers use:

install 'gcc13' or 'gcc13-c++' or one of the other 'gcc13-COMPILER' frontend packages.
override your Makefile to use CC=gcc-13, CXX=g++-13 and similar overrides for the other languages.

For a full changelog with all new GCC13 features, check out
 [link moved to references]

Detailed changes:


CVE-2023-4039: Fixed -fstack-protector issues on aarch64 with variable
 length stack allocations. (bsc#1214052)


Turn cross compiler to s390x to a glibc cross. [bsc#1214460]


Also handle -static-pie in the default-PIE specs

Fixed missed optimization in Skia resulting in Firefox crashes when
 building with LTO. [bsc#1212101]
Make libstdc++6-devel packages own their directories since they
 can be installed standalone. [bsc#1211427]
Add new x86-related intrinsics (amxcomplexintrin.h).
RISC-V: Add support for inlining subword atomic operations Use --enable-link-serialization rather that --enable-link-mutex,
 the benefit of the former one is that the linker jobs are not
 holding tokens of the make's jobserver.
Add cross-bpf packages. See [link moved to references]
 for the general state of BPF with GCC.
Add bootstrap conditional to allow --without=bootstrap to be
 specified to speed up local builds for testing.
Bump included newlib to version 4.3.0.
Also package libhwasan_preinit.o on aarch64.
Configure external timezone database provided by the timezone
 package. Make libstdc++6 recommend timezone to get a fully
 working std::chrono. Install timezone when running the testsuite.
Package libhwasan_preinit.o on x86_64.
Fixed unwinding on aarch64 with pointer signing. [bsc#1206684]
Enable PRU flavour for gcc13 update floatn fixinclude pickup to check each header separately (bsc#1206480)
Redo floatn fixinclude pick-up to simply keep what is there.
Bump libgo SONAME to libgo22.
Do not package libhwasan for biarch (32-bit architecture)
 as the extension depends on 64-bit pointers.
Adjust floatn fixincludes guard to work with SLE12 and earlier
 SLE15.
Depend on at least LLVM 13 for GCN cross compiler.
Update embedded newlib to version 4.2.0 Allow cross-pru-gcc12-bootstrap for armv7l architecture.
 PRU architecture is used for real-time MCUs embedded into TI
 armv7l and aarch64 SoCs. We need to have cross-pru-gcc12 for
 armv7l in order to build both host applications and PRU firmware
 during the same build.");

  script_tag(name:"affected", value:"'gcc13' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libasan8", rpm:"libasan8~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit", rpm:"libasan8-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit-debuginfo", rpm:"libasan8-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-debuginfo", rpm:"libasan8-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0", rpm:"libhwasan0~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0-debuginfo", rpm:"libhwasan0-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit", rpm:"libobjc4-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit-debuginfo", rpm:"libobjc4-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp", rpm:"libstdc++6-pp~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-32bit", rpm:"libstdc++6-pp-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2", rpm:"libtsan2~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2-debuginfo", rpm:"libtsan2-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~13.2.1+git7813~1.6.1", rls:"SLES12.0SP5"))) {
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
