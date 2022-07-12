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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2438.1");
  script_cve_id("CVE-2021-22555", "CVE-2021-33909", "CVE-2021-35039", "CVE-2021-3609", "CVE-2021-3612");
  script_tag(name:"creation_date", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-23 10:28:28 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 17:15:00 +0000 (Fri, 16 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2438-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2438-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212438-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2438-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-22555: A heap out-of-bounds write was discovered in
 net/netfilter/x_tables.c (bnc#1188116).

CVE-2021-33909: Extremely large seq buffer allocations in seq_file could
 lead to buffer underruns and code execution (bsc#1188062).

CVE-2021-3609: A use-after-free in can/bcm could have led to privilege
 escalation (bsc#1187215).

CVE-2021-3612: An out-of-bounds memory write flaw was found in the
 joystick devices subsystem in the way the user calls ioctl JSIOCSBTNMAP.
 This flaw allowed a local user to crash the system or possibly escalate
 their privileges on the system. The highest threat from this
 vulnerability is to confidentiality, integrity, as well as system
 availability (bnc#1187585 ).

CVE-2021-35039: kernel/module.c mishandled Signature Verification, aka
 CID-0c18f29aae7c. Without CONFIG_MODULE_SIG, verification that a kernel
 module is signed, for loading via init_module, did not occur for a
 module.sig_enforce=1 command-line argument (bnc#1188080). NOTE that SUSE
 kernels are configured with CONFIG_MODULE_SIG=y, so are not affected.

The following non-security bugs were fixed:

ACPI: APEI: fix synchronous external aborts in user-mode (git-fixes).

ACPI: bus: Call kobject_put() in acpi_init() error path (git-fixes).

ACPICA: Fix memory leak caused by _CID repair function (git-fixes).

ACPI: EC: Make more Asus laptops use ECDT _GPE (git-fixes).

ACPI: processor idle: Fix up C-state latency if not ordered (git-fixes).

ACPI: property: Constify stubs for CONFIG_ACPI=n case (git-fixes).

ACPI: resources: Add checks for ACPI IRQ override (git-fixes).

ACPI: sysfs: Fix a buffer overrun problem with description_show()
 (git-fixes).

ALSA: hda/realtek: Add another ALC236 variant support (git-fixes).

ALSA: hda/realtek: Fix bass speaker DAC mapping for Asus UM431D
 (git-fixes).

ALSA: intel8x0: Fix breakage at ac97 clock measurement (git-fixes).

ALSA: isa: Fix error return code in snd_cmi8330_probe() (git-fixes).

ALSA: usb-audio: fix rate on Ozone Z90 USB headset (git-fixes).

ALSA: usb-audio: scarlett2: Fix wrong resume call (git-fixes).

ALSA: usb-audio: scarlett2: Read mixer volumes at init time (git-fixes).

ALSA: usb-audio: scarlett2: Read mux at init time (git-fixes).

amdgpu: fix GEM obj leak in amdgpu_display_user_framebuffer_create
 (bsc#1152472)

ASoC: atmel-i2s: Fix usage of capture and playback at the same time
 (git-fixes).

ASoC: cs42l42: Correct definition of CS42L42_ADC_PDN_MASK (git-fixes).

ASoC: hisilicon: fix missing clk_disable_unprepare() on error in
 hi6210_i2s_startup() (git-fixes).

ASoC: mediatek: mtk-btcvsd: Fix an error handling path in
 'mtk_btcvsd_snd_probe()' (git-fixes).

ASoC: rsnd: tidyup loop on rsnd_adg_clk_query() (git-fixes).

ata: ahci_sunxi: Disable DIPM (git-fixes).

ath10k: add missing ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE MicroOS 5.0, SUSE Linux Enterprise Workstation Extension 15-SP2, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise High Availability 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.75.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.75.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.75.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.75.3.9.34.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.75.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.75.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.75.2", rls:"SLES15.0SP2"))) {
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
