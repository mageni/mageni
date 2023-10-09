# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3662.1");
  script_cve_id("CVE-2019-14250", "CVE-2019-15847", "CVE-2020-13844", "CVE-2023-4039");
  script_tag(name:"creation_date", value:"2023-09-19 04:28:11 +0000 (Tue, 19 Sep 2023)");
  script_version("2023-09-19T05:06:02+0000");
  script_tag(name:"last_modification", value:"2023-09-19 05:06:02 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-17 13:38:00 +0000 (Thu, 17 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3662-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3662-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233662-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc7' package(s) announced via the SUSE-SU-2023:3662-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc7 fixes the following issues:
Security issues fixed:

CVE-2023-4039: Fixed incorrect stack protector for C99 VLAs on Aarch64 (bsc#1214052).
CVE-2019-15847: Fixed POWER9 DARN miscompilation. (bsc#1149145)
CVE-2019-14250: Includes fix for LTO linker plugin heap overflow. (bsc#1142649)

Update to GCC 7.5.0 release.
Other changes:

Fixed KASAN kernel compile. (bsc#1205145)
Fixed ICE with C++17 code. (bsc#1204505)
Fixed altivec.h redefining bool in C++ which makes bool unusable (bsc#1195517):
Adjust gnats idea of the target, fixing the build of gprbuild. [bsc#1196861]
Do not handle exceptions in std::thread (jsc#CAR-1182)
add -fpatchable-function-entry feature to gcc-7.
Fixed glibc namespace violation with getauxval. (bsc#1167939)
Backport aarch64 Straight Line Speculation mitigation [bsc#1172798, CVE-2020-13844]
Enable fortran for the nvptx offload compiler.
Update README.First-for.SuSE.packagers Avoid assembler errors with AVX512 gather and scatter instructions when using -masm=intel.
Backport the aarch64 -moutline-atomics feature and accumulated fixes but not its
 default enabling. (jsc#SLE-12209, bsc#1167939)
Fixed memcpy miscompilation on aarch64. (bsc#1178624, bsc#1178577)
Fixed debug line info for try/catch. (bsc#1178614)
Fixed corruption of pass private ->aux via DF. (gcc#94148)
Fixed debug information issue with inlined functions and passed by reference arguments. [gcc#93888]
Fixed register allocation issue with exception handling code on s390x. (bsc#1161913)
Backport PR target/92692 to fix miscompilation of some atomic code on aarch64. (bsc#1150164)
Fixed miscompilation in vectorized code for s390x. (bsc#1160086) [gcc#92950]
Fixed miscompilation with thread-safe local static initialization. [gcc#85887]
Fixed debug info created for array definitions that complete an earlier declaration. [bsc#1146475]
Fixed vector shift miscompilation on s390. (bsc#1141897)
Add gcc7 -flive-patching patch. [bsc#1071995, fate#323487]
Strip -flto from $optflags.
Disables switch jump-tables when retpolines are used. (bsc#1131264, jsc#SLE-6738)
Fixed ICE compiling tensorflow on aarch64. (bsc#1129389)
Fixed for aarch64 FMA steering pass use-after-free. (bsc#1128794)
Fixed ICE compiling tensorflow. (bsc#1129389)
Fixed s390x FP load-and-test issue. (bsc#1124644)
Adjust gnat manual entries in the info directory. (bsc#1114592)
Fixed to no longer try linking -lieee with -mieee-fp. (bsc#1084842)");

  script_tag(name:"affected", value:"'gcc7' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debuginfo", rpm:"gcc7-debuginfo~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debugsource", rpm:"gcc7-debugsource~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit", rpm:"libasan4-32bit~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4", rpm:"libasan4~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-debuginfo", rpm:"libasan4-debuginfo~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit", rpm:"libcilkrts5-32bit~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5", rpm:"libcilkrts5~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-debuginfo", rpm:"libcilkrts5-debuginfo~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit", rpm:"libgfortran4-32bit~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4", rpm:"libgfortran4~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-debuginfo", rpm:"libgfortran4-debuginfo~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit", rpm:"libubsan0-32bit~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0", rpm:"libubsan0~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-debuginfo", rpm:"libubsan0-debuginfo~7.5.0+r278197~13.1", rls:"SLES12.0SP5"))) {
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
