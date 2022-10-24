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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3585.1");
  script_cve_id("CVE-2022-1263", "CVE-2022-2586", "CVE-2022-3202", "CVE-2022-3239", "CVE-2022-3303", "CVE-2022-39189", "CVE-2022-41218", "CVE-2022-41848", "CVE-2022-41849");
  script_tag(name:"creation_date", value:"2022-10-17 05:00:13 +0000 (Mon, 17 Oct 2022)");
  script_version("2022-10-17T11:13:19+0000");
  script_tag(name:"last_modification", value:"2022-10-17 11:13:19 +0000 (Mon, 17 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-08 18:37:00 +0000 (Thu, 08 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3585-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3585-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223585-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3585-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated.

The following security bugs were fixed:

CVE-2022-3303: Fixed a race condition in the sound subsystem due to
 improper locking (bnc#1203769).

CVE-2022-41218: Fixed an use-after-free caused by refcount races in
 drivers/media/dvb-core/dmxdev.c (bnc#1202960).

CVE-2022-3239: Fixed an use-after-free in the video4linux driver that
 could lead a local user to able to crash the system or escalate their
 privileges (bnc#1203552).

CVE-2022-41848: Fixed a race condition and resultant use-after-free if a
 physically proximate attacker removes a PCMCIA device while calling
 ioctl (bnc#1203987).

CVE-2022-41849: Fixed a race condition and resultant use-after-free if a
 physically proximate attacker removes a USB device while calling open
 (bnc#1203992).

CVE-2022-2586: Fixed a use-after-free which can be triggered when a nft
 table is deleted (bnc#1202095).

CVE-2022-1263: Fixed a NULL pointer dereference issue was found in KVM
 when releasing a vCPU with dirty ring support enabled. This flaw allowed
 an unprivileged local attacker on the host to issue specific ioctl
 calls, causing a kernel oops condition that results in a denial of
 service (bnc#1198189).

CVE-2022-3202: Fixed a NULL pointer dereference flaw in Journaled File
 System. This could allow a local attacker to crash the system or leak
 kernel internal information (bnc#1203389).

CVE-2022-39189: Fixed a bug in the x86 KVM subsystem which allows
 unprivileged guest users to compromise the guest kernel because TLB
 flush operations are mishandled (bnc#1203066).

The following non-security bugs were fixed:

ACPI / scan: Create platform device for CS35L41 (bsc#1203699).

ACPI: processor idle: Practically limit 'Dummy wait' workaround to old
 Intel systems (bsc#1203767).

ACPI: resource: skip IRQ override on AMD Zen platforms (git-fixes).

ACPI: scan: Add CLSA0101 Laptop Support (bsc#1203699).

ACPI: utils: Add api to read _SUB from ACPI (bsc#1203699).

ALSA: aloop: Fix random zeros in capture data when using jiffies timer
 (git-fixes).

ALSA: core: Fix double-free at snd_card_new() (git-fixes).

ALSA: cs35l41: Check hw_config before using it (bsc#1203699).

ALSA: cs35l41: Enable Internal Boost in shared lib (bsc#1203699).

ALSA: cs35l41: Move cs35l41_gpio_config to shared lib (bsc#1203699).

ALSA: cs35l41: Unify hardware configuration (bsc#1203699).

ALSA: emu10k1: Fix out of bounds access in
 snd_emu10k1_pcm_channel_alloc() (git-fixes).

ALSA: hda: add Intel 5 Series / 3400 PCI DID (git-fixes).

ALSA: hda: cs35l41: Add Amp Name based on channel and index
 (bsc#1203699).

ALSA: hda: cs35l41: Add Boost type flag (bsc#1203699).

ALSA: hda: cs35l41: Add calls to newly added test key function
 (bsc#1203699).

ALSA: hda: cs35l41: Add defaulted values into dsp bypass config sequence
 (bsc#1203699).

ALSA: hda: cs35l41: Add initial DSP support and firmware loading
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.14.21~150400.14.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.14.21~150400.14.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.14.21~150400.14.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.14.21~150400.14.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.14.21~150400.14.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.14.21~150400.14.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.14.21~150400.14.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.14.21~150400.14.16.1", rls:"SLES15.0SP4"))) {
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
