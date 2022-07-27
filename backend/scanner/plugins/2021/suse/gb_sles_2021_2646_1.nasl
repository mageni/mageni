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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2646.1");
  script_cve_id("CVE-2021-21781", "CVE-2021-22543", "CVE-2021-3659", "CVE-2021-37576");
  script_tag(name:"creation_date", value:"2021-08-11 02:25:15 +0000 (Wed, 11 Aug 2021)");
  script_version("2021-08-11T02:25:15+0000");
  script_tag(name:"last_modification", value:"2021-08-12 10:27:55 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-08 05:15:00 +0000 (Thu, 08 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2646-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2646-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212646-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2646-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-3659: Fixed a NULL pointer dereference in llsec_key_alloc() in
 net/mac802154/llsec.c (bsc#1188876).

CVE-2021-21781: Fixed a information disclosure vulnerability in the ARM
 SIGPAGE (bsc#1188445).

CVE-2021-22543: Fixed improper handling of VM_IO<pipe>VM_PFNMAP vmas in KVM,
 which could bypass RO checks and can lead to pages being freed while
 still accessible by the VMM and guest. This allowed users with the
 ability to start and control a VM to read/write random pages of memory
 and can result in local privilege escalation (bsc#1186482).

CVE-2021-37576: Fixed an issue on the powerpc platform, where a KVM
 guest OS user could cause host OS memory corruption via rtas_args.nargs
 (bsc#1188838).

The following non-security bugs were fixed:

ACPI: AMBA: Fix resource name in /proc/iomem (git-fixes).

ACPI: video: Add quirk for the Dell Vostro 3350 (git-fixes).

ALSA: ac97: fix PM reference leak in ac97_bus_remove() (git-fixes).

ALSA: bebob: add support for ToneWeal FW66 (git-fixes).

ALSA: hda: Add IRQ check for platform_get_irq() (git-fixes).

ALSA: hdmi: Expose all pins on MSI MS-7C94 board (git-fixes).

ALSA: ppc: fix error return code in snd_pmac_probe() (git-fixes).

ALSA: sb: Fix potential ABBA deadlock in CSP driver (git-fixes).

ALSA: sb: Fix potential double-free of CSP mixer elements (git-fixes).

ALSA: usb-audio: Add registration quirk for JBL Quantum headsets
 (git-fixes).

ALSA: usb-audio: scarlett2: Fix 18i8 Gen 2 PCM Input count (git-fixes).

ALSA: usb-audio: scarlett2: Fix 6i6 Gen 2 line out descriptions
 (git-fixes).

ALSA: usb-audio: scarlett2: Fix data_mutex lock (git-fixes).

ALSA: usb-audio: scarlett2: Fix scarlett2_*_ctl_put() return values
 (git-fixes).

ALSA: usx2y: Do not call free_pages_exact() with NULL address
 (git-fixes).

ARM: ensure the signal page contains defined contents (bsc#1188445).

ASoC: Intel: kbl_da7219_max98357a: shrink platform_id below 20
 characters (git-fixes).

ASoC: img: Fix PM reference leak in img_i2s_in_probe() (git-fixes).

ASoC: rt5631: Fix regcache sync errors on resume (git-fixes).

ASoC: soc-core: Fix the error return code in
 snd_soc_of_parse_audio_routing() (git-fixes).

ASoC: tegra: Set driver_name=tegra for all machine drivers (git-fixes).

Bluetooth: Fix the HCI to MGMT status conversion table (git-fixes).

Bluetooth: Shutdown controller after workqueues are flushed or cancelled
 (git-fixes).

Bluetooth: btusb: Fixed too many in-token issue for Mediatek Chip
 (git-fixes).

Bluetooth: btusb: fix bt fiwmare downloading failure issue for qca btsoc
 (git-fixes).

Input: hideep - fix the uninitialized use in hideep_nvm_unlock()
 (git-fixes).

Input: ili210x - add missing negation for touch indication on ili210x
 (git-fixes).

KVM: LAPIC: Prevent setting the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.61.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.61.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.61.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.61.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.61.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.61.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.61.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.61.1", rls:"SLES15.0SP2"))) {
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
