# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0394.1");
  script_cve_id("CVE-2020-24588", "CVE-2022-4382", "CVE-2022-47929", "CVE-2023-0179", "CVE-2023-0266");
  script_tag(name:"creation_date", value:"2023-02-14 04:19:30 +0000 (Tue, 14 Feb 2023)");
  script_version("2023-02-14T10:18:49+0000");
  script_tag(name:"last_modification", value:"2023-02-14 10:18:49 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:47:00 +0000 (Mon, 06 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0394-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0394-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230394-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0394-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 AZURE kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2023-0266: Fixed a use-after-free vulnerability inside the ALSA PCM
 package. SNDRV_CTL_IOCTL_ELEM_{READ<pipe>WRITE}32 was missing locks that
 could have been used in a use-after-free that could have resulted in a
 priviledge escalation to gain ring0 access from the system user
 (bsc#1207134).

CVE-2023-0179: Fixed incorrect arithmetics when fetching VLAN header
 bits (bsc#1207034).

CVE-2022-47929: Fixed NULL pointer dereference bug in the traffic
 control subsystem (bnc#1207237).

CVE-2022-4382: Fixed a use-after-free flaw that was caused by a race
 condition among the superblock operations inside the gadgetfs code
 (bsc#1206258).

CVE-2020-24588: Fixed injection of arbitrary network packets against
 devices that support receiving non-SSP A-MSDU frames (which is mandatory
 as part of 802.11n) (bsc#1199701).

The following non-security bugs were fixed:

ACPI: EC: Fix EC address space handler unregistration (bsc#1207149).

ACPI: EC: Fix ECDT probe ordering issues (bsc#1207149).

ACPI: PRM: Check whether EFI runtime is available (git-fixes).

ACPICA: Allow address_space_handler Install and _REG execution as 2
 separate steps (bsc#1207149).

ACPICA: include/acpi/acpixf.h: Fix indentation (bsc#1207149).

ALSA: control-led: use strscpy in set_led_id() (git-fixes).

ALSA: hda - Enable headset mic on another Dell laptop with ALC3254
 (git-fixes).

ALSA: hda/hdmi: Add a HP device 0x8715 to force connect list (git-fixes).

ALSA: hda/realtek - Turn on power early (git-fixes).

ALSA: hda/realtek: Add Acer Predator PH315-54 (git-fixes).

ALSA: hda/realtek: Enable mute/micmute LEDs on HP Spectre x360 13-aw0xxx
 (git-fixes).

ALSA: hda/realtek: fix mute/micmute LEDs do not work for a HP platform
 (git-fixes).

ALSA: hda/realtek: fix mute/micmute LEDs for a HP ProBook (git-fixes).

ALSA: hda/realtek: fix mute/micmute LEDs, speaker do not work for a HP
 platform (git-fixes).

ALSA: hda/via: Avoid potential array out-of-bound in
 add_secret_dac_path() (git-fixes).

ALSA: hda: cs35l41: Check runtime suspend capability at runtime_idle
 (git-fixes).

ALSA: hda: cs35l41: Do not return -EINVAL from system suspend/resume
 (git-fixes).

ALSA: pcm: Move rwsem lock inside snd_ctl_elem_read to prevent UAF
 (git-fixes).

ALSA: usb-audio: Make sure to stop endpoints before closing EPs
 (git-fixes).

ALSA: usb-audio: Relax hw constraints for implicit fb sync (git-fixes).

ARM: dts: at91: sam9x60: fix the ddr clock for sam9x60 (git-fixes).

ARM: dts: imx6qdl-gw560x: Remove incorrect 'uart-has-rtscts' (git-fixes).

ARM: dts: imx6ul-pico-dwarf: Use 'clock-frequency' (git-fixes).

ARM: dts: imx7d-pico: Use 'clock-frequency' (git-fixes).

ARM: dts: imx: Fix pca9547 i2c-mux node name (git-fixes).

ARM: dts: vf610: Fix pca9548 i2c-mux node names ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.14.21~150400.14.34.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.14.21~150400.14.34.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.14.21~150400.14.34.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.14.21~150400.14.34.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.14.21~150400.14.34.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.14.21~150400.14.34.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.14.21~150400.14.34.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.14.21~150400.14.34.1", rls:"SLES15.0SP4"))) {
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
