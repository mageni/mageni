# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853372");
  script_version("2020-08-26T13:56:52+0000");
  script_cve_id("CVE-2020-0305", "CVE-2020-10135", "CVE-2020-10781", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-15780", "CVE-2020-16166");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-27 11:59:41 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-22 03:00:47 +0000 (Sat, 22 Aug 2020)");
  script_name("openSUSE: Security Advisory for the (openSUSE-SU-2020:1236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1236-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00047.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2020:1236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 15.2 kernel was updated to receive various security and
  bugfixes.

  This update is signed with the new UEFI signing key for openSUSE. It
  contains rebuilds of all available KMP packages also rebuilt with the new
  UEFi signing key. (boo#1174543)

  The following security bugs were fixed:

  - CVE-2020-14356: A use after free vulnerability in cgroup BPF component
  was fixed (bsc#1175213).

  - CVE-2020-14331: A buffer over write in vgacon_scroll was fixed
  (bnc#1174205).

  - CVE-2020-16166: The Linux kernel allowed remote attackers to make
  observations that help to obtain sensitive information about the
  internal state of the network RNG, aka CID-f227e3ec3b5c. This is related
  to drivers/char/random.c and kernel/time/timer.c (bnc#1174757).

  - CVE-2020-10135: Legacy pairing and secure-connections pairing
  authentication in Bluetooth BR/EDR Core Specification v5.2 and earlier
  may have allowed an unauthenticated user to complete authentication
  without pairing credentials via adjacent access. An unauthenticated,
  adjacent attacker could impersonate a Bluetooth BR/EDR master or slave
  to pair with a previously paired remote device to successfully complete
  the authentication procedure without knowing the link key (bnc#1171988).

  - CVE-2020-0305: In cdev_get of char_dev.c, there is a possible
  use-after-free due to a race condition. This could lead to local
  escalation of privilege with System execution privileges needed. User
  interaction is not needed for exploitation (bnc#1174462).

  - CVE-2020-15780: An issue was discovered in drivers/acpi/acpi_configfs.c
  in the Linux kernel Injection of malicious ACPI tables via configfs
  could be used by attackers to bypass lockdown and secure boot
  restrictions, aka CID-75b0cea7bf30 (bnc#1173573).

  - CVE-2020-10781: zram sysfs resource consumption was fixed (bnc#1173074).

  The following non-security bugs were fixed:

  - 9p/trans_fd: Fix concurrency del of req_list in
  p9_fd_cancelled/p9_read_work (git-fixes).

  - ACPICA: Dispatcher: add status checks (git-fixes).

  - ACPI/IORT: Fix PMCG node single ID mapping handling (git-fixes).

  - ACPI: video: Use native backlight on Acer Aspire 5783z (git-fixes).

  - ACPI: video: Use native backlight on Acer TravelMate 5735Z (git-fixes).

  - af_key: pfkey_dump needs parameter validation (git-fixes).

  - agp/intel: Fix a memory leak on module initialisation failure
  (git-fixes).

  - ALSA: asihpi: delete duplicated word (git-fixes).

  - ALSA: atmel: Remove invalid 'fall through' comments (git-fixes).

  - ALSA: core: pcm_iec958: fix kernel-doc (git-fixes).

  - ALSA: ec ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"dpdk-doc", rpm:"dpdk-doc~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch", rpm:"bbswitch~0.8~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-debugsource", rpm:"bbswitch-debugsource~0.8~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-kmp-default", rpm:"bbswitch-kmp-default~0.8_k5.3.18_lp152.36~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-kmp-default-debuginfo", rpm:"bbswitch-kmp-default-debuginfo~0.8_k5.3.18_lp152.36~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-kmp-preempt", rpm:"bbswitch-kmp-preempt~0.8_k5.3.18_lp152.36~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-kmp-preempt-debuginfo", rpm:"bbswitch-kmp-preempt-debuginfo~0.8_k5.3.18_lp152.36~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash", rpm:"crash~7.2.8~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-debuginfo", rpm:"crash-debuginfo~7.2.8~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-debugsource", rpm:"crash-debugsource~7.2.8~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-devel", rpm:"crash-devel~7.2.8~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-doc", rpm:"crash-doc~7.2.8~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-eppic", rpm:"crash-eppic~7.2.8~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-eppic-debuginfo", rpm:"crash-eppic-debuginfo~7.2.8~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-gcore", rpm:"crash-gcore~7.2.8~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-gcore-debuginfo", rpm:"crash-gcore-debuginfo~7.2.8~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-default", rpm:"crash-kmp-default~7.2.8_k5.3.18_lp152.36~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-default-debuginfo", rpm:"crash-kmp-default-debuginfo~7.2.8_k5.3.18_lp152.36~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-preempt", rpm:"crash-kmp-preempt~7.2.8_k5.3.18_lp152.36~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-preempt-debuginfo", rpm:"crash-kmp-preempt-debuginfo~7.2.8_k5.3.18_lp152.36~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk", rpm:"dpdk~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debuginfo", rpm:"dpdk-debuginfo~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debugsource", rpm:"dpdk-debugsource~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel", rpm:"dpdk-devel~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel-debuginfo", rpm:"dpdk-devel-debuginfo~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-examples", rpm:"dpdk-examples~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-examples-debuginfo", rpm:"dpdk-examples-debuginfo~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default", rpm:"dpdk-kmp-default~19.11.1_k5.3.18_lp152.36~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default-debuginfo", rpm:"dpdk-kmp-default-debuginfo~19.11.1_k5.3.18_lp152.36~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-preempt", rpm:"dpdk-kmp-preempt~19.11.1_k5.3.18_lp152.36~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-preempt-debuginfo", rpm:"dpdk-kmp-preempt-debuginfo~19.11.1_k5.3.18_lp152.36~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools", rpm:"dpdk-tools~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools-debuginfo", rpm:"dpdk-tools-debuginfo~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd", rpm:"drbd~9.0.22~1+git.fe2b5983~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-debugsource", rpm:"drbd-debugsource~9.0.22~1+git.fe2b5983~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-kmp-default", rpm:"drbd-kmp-default~9.0.22~1+git.fe2b5983_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>drbd-kmp-default-debuginfo", rpm:"<br>drbd-kmp-default-debuginfo~9.0.22~1+git.fe2b5983_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-kmp-preempt", rpm:"drbd-kmp-preempt~9.0.22~1+git.fe2b5983_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>drbd-kmp-preempt-debuginfo", rpm:"<br>drbd-kmp-preempt-debuginfo~9.0.22~1+git.fe2b5983_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-debugsource", rpm:"hdjmod-debugsource~1.28~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-default", rpm:"hdjmod-kmp-default~1.28_k5.3.18_lp152.36~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-default-debuginfo", rpm:"hdjmod-kmp-default-debuginfo~1.28_k5.3.18_lp152.36~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-preempt", rpm:"hdjmod-kmp-preempt~1.28_k5.3.18_lp152.36~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-preempt-debuginfo", rpm:"hdjmod-kmp-preempt-debuginfo~1.28_k5.3.18_lp152.36~lp152.6.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debuginfo", rpm:"kernel-kvmsmall-debuginfo~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debugsource", rpm:"kernel-kvmsmall-debugsource~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel-debuginfo", rpm:"kernel-kvmsmall-devel-debuginfo~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~lp152.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-20_0", rpm:"libdpdk-20_0~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-20_0-debuginfo", rpm:"libdpdk-20_0-debuginfo~19.11.1~lp152.2.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mhvtl", rpm:"mhvtl~1.62~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mhvtl-debuginfo", rpm:"mhvtl-debuginfo~1.62~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mhvtl-debugsource", rpm:"mhvtl-debugsource~1.62~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mhvtl-kmp-default", rpm:"mhvtl-kmp-default~1.62_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mhvtl-kmp-default-debuginfo", rpm:"mhvtl-kmp-default-debuginfo~1.62_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mhvtl-kmp-preempt", rpm:"mhvtl-kmp-preempt~1.62_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mhvtl-kmp-preempt-debuginfo", rpm:"mhvtl-kmp-preempt-debuginfo~1.62_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-authlibs", rpm:"openafs-authlibs~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-authlibs-debuginfo", rpm:"openafs-authlibs-debuginfo~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-authlibs-devel", rpm:"openafs-authlibs-devel~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-client", rpm:"openafs-client~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-client-debuginfo", rpm:"openafs-client-debuginfo~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-debuginfo", rpm:"openafs-debuginfo~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-debugsource", rpm:"openafs-debugsource~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-devel", rpm:"openafs-devel~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-devel-debuginfo", rpm:"openafs-devel-debuginfo~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-fuse_client", rpm:"openafs-fuse_client~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-fuse_client-debuginfo", rpm:"openafs-fuse_client-debuginfo~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-kernel-source", rpm:"openafs-kernel-source~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-kmp-default", rpm:"openafs-kmp-default~1.8.5_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-kmp-default-debuginfo", rpm:"openafs-kmp-default-debuginfo~1.8.5_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-kmp-preempt", rpm:"openafs-kmp-preempt~1.8.5_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-kmp-preempt-debuginfo", rpm:"openafs-kmp-preempt-debuginfo~1.8.5_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-server", rpm:"openafs-server~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-server-debuginfo", rpm:"openafs-server-debuginfo~1.8.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock", rpm:"pcfclock~0.44~lp152.4.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-debuginfo", rpm:"pcfclock-debuginfo~0.44~lp152.4.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-debugsource", rpm:"pcfclock-debugsource~0.44~lp152.4.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-default", rpm:"pcfclock-kmp-default~0.44_k5.3.18_lp152.36~lp152.4.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-default-debuginfo", rpm:"pcfclock-kmp-default-debuginfo~0.44_k5.3.18_lp152.36~lp152.4.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-preempt", rpm:"pcfclock-kmp-preempt~0.44_k5.3.18_lp152.36~lp152.4.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-preempt-debuginfo", rpm:"pcfclock-kmp-preempt-debuginfo~0.44_k5.3.18_lp152.36~lp152.4.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtl8812au", rpm:"rtl8812au~5.6.4.2+git20200318.49e98ff~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtl8812au-debugsource", rpm:"rtl8812au-debugsource~5.6.4.2+git20200318.49e98ff~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>rtl8812au-kmp-default", rpm:"<br>rtl8812au-kmp-default~5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>rtl8812au-kmp-default-debuginfo", rpm:"<br>rtl8812au-kmp-default-debuginfo~5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>rtl8812au-kmp-preempt", rpm:"<br>rtl8812au-kmp-preempt~5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>rtl8812au-kmp-preempt-debuginfo", rpm:"<br>rtl8812au-kmp-preempt-debuginfo~5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysdig", rpm:"sysdig~0.26.5~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysdig-debuginfo", rpm:"sysdig-debuginfo~0.26.5~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysdig-debugsource", rpm:"sysdig-debugsource~0.26.5~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysdig-kmp-default", rpm:"sysdig-kmp-default~0.26.5_k5.3.18_lp152.36~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysdig-kmp-default-debuginfo", rpm:"sysdig-kmp-default-debuginfo~0.26.5_k5.3.18_lp152.36~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysdig-kmp-preempt", rpm:"sysdig-kmp-preempt~0.26.5_k5.3.18_lp152.36~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysdig-kmp-preempt-debuginfo", rpm:"sysdig-kmp-preempt-debuginfo~0.26.5_k5.3.18_lp152.36~lp152.3.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v4l2loopback-debugsource", rpm:"v4l2loopback-debugsource~0.12.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v4l2loopback-kmp-default", rpm:"v4l2loopback-kmp-default~0.12.5_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v4l2loopback-kmp-default-debuginfo", rpm:"v4l2loopback-kmp-default-debuginfo~0.12.5_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v4l2loopback-kmp-preempt", rpm:"v4l2loopback-kmp-preempt~0.12.5_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v4l2loopback-kmp-preempt-debuginfo", rpm:"v4l2loopback-kmp-preempt-debuginfo~0.12.5_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v4l2loopback-utils", rpm:"v4l2loopback-utils~0.12.5~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-default", rpm:"vhba-kmp-default~20200106_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-default-debuginfo", rpm:"vhba-kmp-default-debuginfo~20200106_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-preempt", rpm:"vhba-kmp-preempt~20200106_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-preempt-debuginfo", rpm:"vhba-kmp-preempt-debuginfo~20200106_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~6.1.10_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default-debuginfo", rpm:"virtualbox-kmp-default-debuginfo~6.1.10_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt", rpm:"virtualbox-kmp-preempt~6.1.10_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-preempt-debuginfo", rpm:"virtualbox-kmp-preempt-debuginfo~6.1.10_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~6.1.10~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons", rpm:"xtables-addons~3.9~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-debuginfo", rpm:"xtables-addons-debuginfo~3.9~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-default", rpm:"xtables-addons-kmp-default~3.9_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-default-debuginfo", rpm:"xtables-addons-kmp-default-debuginfo~3.9_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-preempt", rpm:"xtables-addons-kmp-preempt~3.9_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-preempt-debuginfo", rpm:"xtables-addons-kmp-preempt-debuginfo~3.9_k5.3.18_lp152.36~lp152.2.2.1", rls:"openSUSELeap15.2"))) {
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
