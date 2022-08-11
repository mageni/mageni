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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2722.1");
  script_cve_id("CVE-2021-33655", "CVE-2022-1462", "CVE-2022-21505", "CVE-2022-29581", "CVE-2022-32250");
  script_tag(name:"creation_date", value:"2022-08-10 04:21:08 +0000 (Wed, 10 Aug 2022)");
  script_version("2022-08-10T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-08-10 10:11:40 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-12 02:27:00 +0000 (Sun, 12 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2722-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2722-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222722-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2722-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-33655: Fixed out of bounds write with ioctl FBIOPUT_VSCREENINFO
 (bnc#1201635).

CVE-2022-1462: Fixed an out-of-bounds read flaw in the TeleTYpe
 subsystem (bnc#1198829).

CVE-2022-21505: Fixed kexec lockdown bypass with IMA policy
 (bsc#1201458).

CVE-2022-29581: Fixed improper update of Reference Count in net/sched
 that could cause root privilege escalation (bnc#1199665).

CVE-2022-32250: Fixed an use-after-free bug in the netfilter subsystem.
 This flaw allowed a local attacker with user access to cause a privilege
 escalation issue (bnc#1200015, bnc#1200494).

The following non-security bugs were fixed:

9p: Fix refcounting during full path walks for fid lookups (git-fixes).

9p: fix fid refcount leak in v9fs_vfs_atomic_open_dotl (git-fixes).

9p: fix fid refcount leak in v9fs_vfs_get_link (git-fixes).

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

ARM: 9216/1: Fix MAX_DMA_ADDRESS overflow (git-fixes).

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
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.14.21~150400.14.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.14.21~150400.14.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.14.21~150400.14.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.14.21~150400.14.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.14.21~150400.14.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.14.21~150400.14.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.14.21~150400.14.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.14.21~150400.14.10.1", rls:"SLES15.0SP4"))) {
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
