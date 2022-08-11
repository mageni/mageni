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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2202.1");
  script_cve_id("CVE-2020-26558", "CVE-2020-36385", "CVE-2020-36386", "CVE-2021-0129");
  script_tag(name:"creation_date", value:"2021-07-01 13:05:51 +0000 (Thu, 01 Jul 2021)");
  script_version("2021-07-01T13:05:51+0000");
  script_tag(name:"last_modification", value:"2021-07-01 13:05:51 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 15:08:00 +0000 (Wed, 16 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2202-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2202-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212202-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2202-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-26558: Bluetooth LE and BR/EDR secure pairing in Bluetooth Core
 Specification 2.1 may permit a nearby man-in-the-middle attacker to
 identify the Passkey used during pairing by reflection of the public key
 and the authentication evidence of the initiating device, potentially
 permitting this attacker to complete authenticated pairing with the
 responding device using the correct Passkey for the pairing session.
 (bnc#1179610 bnc#1186463)

CVE-2021-0129: Improper access control in BlueZ may have allowed an
 authenticated user to potentially enable information disclosure via
 adjacent access (bnc#1186463).

CVE-2020-36385: Fixed a use-after-free in drivers/infiniband/core/ucma.c
 which could be triggered if the ctx is reached via the ctx_list in some
 ucma_migrate_id situations where ucma_close is called (bnc#1187050).

CVE-2020-36386: Fixed a slab out-of-bounds read in
 hci_extended_inquiry_result_evt (bnc#1187038).

The following non-security bugs were fixed:

ACPICA: Clean up context mutex during object deletion (git-fixes).

ALSA: hda/cirrus: Set Initial DMIC volume to -26 dB (git-fixes).

ALSA: hda/realtek: fix mute/micmute LEDs and speaker for HP Elite
 Dragonfly G2 (git-fixes).

ALSA: hda/realtek: fix mute/micmute LEDs and speaker for HP EliteBook
 x360 1040 G8 (git-fixes).

ALSA: hda/realtek: fix mute/micmute LEDs for HP EliteBook 840 Aero G8
 (git-fixes).

ALSA: hda/realtek: fix mute/micmute LEDs for HP ZBook Power G8
 (git-fixes).

ALSA: hda/realtek: headphone and mic do not work on an Acer laptop
 (git-fixes).

ALSA: hda: Fix for mute key LED for HP Pavilion 15-CK0xx (git-fixes).

ALSA: hda: Fix for mute key LED for HP Pavilion 15-CK0xx (git-fixes).

ALSA: hda: update the power_state during the direct-complete (git-fixes).

ALSA: seq: Fix race of snd_seq_timer_open() (git-fixes).

ALSA: timer: Fix master timer notification (git-fixes).

ASoC: Intel: soc-acpi: remove TGL RVP mixed SoundWire/TDM config
 (git-fixes).

ASoC: amd: fix for pcm_read() error (git-fixes).

ASoC: cs43130: handle errors in cs43130_probe() properly (git-fixes).

ASoC: max98088: fix ni clock divider calculation (git-fixes).

Bluetooth: fix the erroneous flush_work() order (git-fixes).

Enable CONFIG_PCI_PF_STUB for Nvidia Ampere vGPU support (jsc#SLE-17882
 jsc#ECO-3691)

HID: i2c-hid: Skip ELAN power-on command after reset (git-fixes).

HID: i2c-hid: fix format string mismatch (git-fixes).

HID: magicmouse: fix NULL-deref on disconnect (git-fixes).

HID: multitouch: require Finger field to mark Win8 reports as MT
 (git-fixes).

HID: pidff: fix error return code in hid_pidff_init() (git-fixes).

NFC: SUSE specific brutal fix for runtime PM (bsc#1185589).

NFS: Deal correctly with attribute generation counter overflow
 (git-fixes).

NFS: Do no... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP3");

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

if(release == "SLES15.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~38.8.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~38.8.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~38.8.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~38.8.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~38.8.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~38.8.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~38.8.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~38.8.1", rls:"SLES15.0SP3"))){
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
