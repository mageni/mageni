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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0755.1");
  script_cve_id("CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0492", "CVE-2022-0516", "CVE-2022-0847", "CVE-2022-25375");
  script_tag(name:"creation_date", value:"2022-03-09 04:10:18 +0000 (Wed, 09 Mar 2022)");
  script_version("2022-03-09T04:10:18+0000");
  script_tag(name:"last_modification", value:"2022-03-09 11:12:38 +0000 (Wed, 09 Mar 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 18:22:00 +0000 (Mon, 28 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0755-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0755-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220755-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0755-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive various security and bugfixes.


Transient execution side-channel attacks attacking the Branch History Buffer (BHB), named 'Branch Target Injection' and 'Intra-Mode Branch History Injection' are now mitigated.

The following security bugs were fixed:

CVE-2022-0847: Fixed a vulnerability were a local attackers could
 overwrite data in arbitrary (read-only) files (bsc#1196584).

CVE-2022-0001: Fixed Branch History Injection vulnerability
 (bsc#1191580).

CVE-2022-0002: Fixed Intra-Mode Branch Target Injection vulnerability
 (bsc#1191580).

CVE-2022-25375: The RNDIS USB gadget lacks validation of the size of the
 RNDIS_MSG_SET command. Attackers can obtain sensitive information from
 kernel memory (bsc#1196235).

CVE-2022-0516: Fixed missing check in ioctl related to KVM in s390
 allows kernel memory read/write (bsc#1195516).

CVE-2022-0492: Fixed a privilege escalation related to cgroups v1
 release_agent feature, which allowed bypassing namespace isolation
 unexpectedly (bsc#1195543).

The following non-security bugs were fixed:

ACPI/IORT: Check node revision for PMCG resources (git-fixes).

ALSA: hda/realtek: Add missing fixup-model entry for Gigabyte X570
 ALC1220 quirks (git-fixes).

ALSA: hda/realtek: Add quirk for ASUS GU603 (git-fixes).

ALSA: hda/realtek: Fix silent output on Gigabyte X570 Aorus Xtreme after
 reboot from Windows (git-fixes).

ALSA: hda/realtek: Fix silent output on Gigabyte X570S Aorus Master
 (newer chipset) (git-fixes).

ALSA: hda: Fix missing codec probe on Shenker Dock 15 (git-fixes).

ALSA: hda: Fix regression on forced probe mask option (git-fixes).

ALSA: usb-audio: Correct quirk for VF0770 (git-fixes).

ALSA: usb-audio: initialize variables that could ignore errors
 (git-fixes).

ASoC: Revert 'ASoC: mediatek: Check for error clk pointer' (git-fixes).

ASoC: cpcap: Check for NULL pointer after calling of_get_child_by_name
 (git-fixes).

ASoC: fsl: Add missing error handling in pcm030_fabric_probe (git-fixes).

ASoC: max9759: fix underflow in speaker_gain_control_put() (git-fixes).

ASoC: ops: Fix stereo change notifications in snd_soc_put_volsw()
 (git-fixes).

ASoC: ops: Fix stereo change notifications in snd_soc_put_volsw_range()
 (git-fixes).

ASoC: ops: Reject out of bounds values in snd_soc_put_volsw()
 (git-fixes).

ASoC: ops: Reject out of bounds values in snd_soc_put_volsw_sx()
 (git-fixes).

ASoC: ops: Reject out of bounds values in snd_soc_put_xr_sx()
 (git-fixes).

ASoC: xilinx: xlnx_formatter_pcm: Make buffer bytes multiple of period
 bytes (git-fixes).

Align s390 NVME target options with other architectures (bsc#1188404,
 jsc#SLE-22494).

Bluetooth: refactor malicious adv data check (git-fixes).

EDAC/xgene: Fix deferred probing (bsc#1178134).

HID:Add support for UGTABLET WP5540 (git-fixes).

IB/cm: Avoid a loop when device has 255 ports ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.47.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.47.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.47.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.47.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.47.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.47.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.47.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.47.1", rls:"SLES15.0SP3"))) {
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
