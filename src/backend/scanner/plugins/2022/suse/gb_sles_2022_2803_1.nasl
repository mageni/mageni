# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2803.1");
  script_cve_id("CVE-2021-33655", "CVE-2022-21505", "CVE-2022-2585", "CVE-2022-26373", "CVE-2022-29581");
  script_tag(name:"creation_date", value:"2022-08-15 04:45:26 +0000 (Mon, 15 Aug 2022)");
  script_version("2022-08-15T10:11:29+0000");
  script_tag(name:"last_modification", value:"2022-08-15 10:11:29 +0000 (Mon, 15 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 00:05:00 +0000 (Thu, 26 May 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2803-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2803-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222803-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2803-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-33655: Fixed out of bounds write with ioctl FBIOPUT_VSCREENINFO
 (bnc#1201635).

CVE-2022-2585: Fixed use-after-free in POSIX CPU timer (bnc#1202094).

CVE-2022-21505: Fixed kexec lockdown bypass with IMA policy
 (bsc#1201458).

CVE-2022-26373: Fixed CPU info leak via post-barrier RSB predictions
 (bsc#1201726).

CVE-2022-29581: Fixed improper update of Reference Count in net/sched
 that could cause root privilege escalation (bnc#1199665).

The following non-security bugs were fixed:

ACPI: CPPC: Only probe for _CPC if CPPC v2 is acked (git-fixes).

ACPI: video: Fix acpi_video_handles_brightness_key_presses() (git-fixes).

ALSA: hda - Add fixup for Dell Latitidue E5430 (git-fixes).

ALSA: hda/conexant: Apply quirk for another HP ProDesk 600 G3 model
 (git-fixes).

ALSA: hda/realtek - Enable the headset-mic on a Xiaomi's laptop
 (git-fixes).

ALSA: hda/realtek - Fix headset mic problem for a HP machine with alc221
 (git-fixes).

ALSA: hda/realtek - Fix headset mic problem for a HP machine with alc671
 (git-fixes).

ALSA: hda/realtek: Add quirk for Clevo L140PU (git-fixes).

ALSA: hda/realtek: Fix headset mic for Acer SF313-51 (git-fixes).

ALSA: hda/realtek: fix mute/micmute LEDs for HP machines (git-fixes).

ALSA: usb-audio: Add quirk for Fiero SC-01 (fw v1.0.0) (git-fixes).

ALSA: usb-audio: Add quirk for Fiero SC-01 (git-fixes).

ALSA: usb-audio: Add quirks for MacroSilicon MS2100/MS2106 devices
 (git-fixes).

ALSA: usb-audio: Workarounds for Behringer UMC 204/404 HD (git-fixes).

ARM: 9209/1: Spectre-BHB: avoid pr_info() every time a CPU comes out of
 idle (git-fixes).

ARM: 9210/1: Mark the FDT_FIXED sections as shareable (git-fixes).

ARM: 9213/1: Print message about disabled Spectre workarounds only once
 (git-fixes).

ARM: 9214/1: alignment: advance IT state after emulating Thumb
 instruction (git-fixes).

ARM: dts: at91: sama5d2: Fix typo in i2s1 node (git-fixes).

ARM: dts: imx6qdl-ts7970: Fix ngpio typo and count (git-fixes).

ARM: dts: stm32: use the correct clock source for CEC on stm32mp151
 (git-fixes).

ARM: dts: sunxi: Fix SPI NOR campatible on Orange Pi Zero (git-fixes).

ASoC: Intel: Skylake: Correct the handling of fmt_config flexible array
 (git-fixes).

ASoC: Intel: Skylake: Correct the ssp rate discovery in
 skl_get_ssp_clks() (git-fixes).

ASoC: Intel: bytcr_wm5102: Fix GPIO related probe-ordering problem
 (git-fixes).

ASoC: Intel: sof_sdw: handle errors on card registration (git-fixes).

ASoC: Realtek/Maxim SoundWire codecs: disable pm_runtime on remove
 (git-fixes).

ASoC: Remove unused hw_write_t type (git-fixes).

ASoC: SOF: Intel: hda-loader: Clarify the cl_dsp_init() flow (git-fixes).

ASoC: codecs: rt700/rt711/rt711-sdca: initialize workqueues in probe
 (git-fixes).

ASoC: codecs: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP4, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Development Tools 15-SP4, SUSE Linux Enterprise Module for Legacy Software 15-SP4, SUSE Linux Enterprise Module for Live Patching 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.18.1.150400.24.5.4", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.14.21~150400.24.18.1", rls:"SLES15.0SP4"))) {
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
