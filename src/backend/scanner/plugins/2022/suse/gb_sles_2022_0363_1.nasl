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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0363.1");
  script_cve_id("CVE-2020-28097", "CVE-2021-22600", "CVE-2021-39648", "CVE-2021-39657", "CVE-2021-39685", "CVE-2021-4159", "CVE-2021-44733", "CVE-2021-45095", "CVE-2022-0286", "CVE-2022-0330", "CVE-2022-0435", "CVE-2022-22942");
  script_tag(name:"creation_date", value:"2022-02-11 03:25:31 +0000 (Fri, 11 Feb 2022)");
  script_version("2022-02-11T10:30:56+0000");
  script_tag(name:"last_modification", value:"2022-02-11 11:02:08 +0000 (Fri, 11 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-04 20:53:00 +0000 (Fri, 04 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0363-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0363-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220363-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0363-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-0435: Fixed remote stack overflow in net/tipc module that
 validate domain record count on input (bsc#1195254).

CVE-2022-0330: Fixed flush TLBs before releasing backing store
 (bsc#1194880).

CVE-2022-0286: Fixed null pointer dereference in bond_ipsec_add_sa()
 that may have lead to local denial of service (bnc#1195371).

CVE-2022-22942: Fixed stale file descriptors on failed usercopy
 (bsc#1195065).

CVE-2021-45095: Fixed refcount leak in pep_sock_accept in
 net/phonet/pep.c (bnc#1193867).

CVE-2021-44733: Fixed a use-after-free exists in drivers/tee/tee_shm.c
 in the TEE subsystem, that could have occurred because of a race
 condition in tee_shm_get_from_id during an attempt to free a shared
 memory object (bnc#1193767).

CVE-2021-39657: Fixed out of bounds read due to a missing bounds check
 in ufshcd_eh_device_reset_handler of ufshcd.c. This could lead to local
 information disclosure with System execution privileges needed
 (bnc#1193864).

CVE-2021-39648: Fixed possible disclosure of kernel heap memory due to a
 race condition in gadget_dev_desc_UDC_show of configfs.c. This could
 lead to local information disclosure with System execution privileges
 needed. User interaction is not needed for exploitation (bnc#1193861).

CVE-2021-22600: Fixed double free bug in packet_set_ring() in
 net/packet/af_packet.c that could have been exploited by a local user
 through crafted syscalls to escalate privileges or deny service
 (bnc#1195184).

CVE-2020-28097: Fixed out-of-bounds read in vgacon subsystem that
 mishandled software scrollback (bnc#1187723).

CVE-2021-4159: Fixed kernel ptr leak vulnerability via BPF in
 coerce_reg_to_size (bsc#1194227).


The following security references were added to already fixed issues:

CVE-2021-39685: Fixed USB gadget buffer overflow caused by too large
 endpoint 0 requests (bsc#1193802).


The following non-security bugs were fixed:

ACPI: battery: Add the ThinkPad 'Not Charging' quirk (git-fixes).

ACPICA: Executer: Fix the REFCLASS_REFOF case in
 acpi_ex_opcode_1A_0T_1R() (git-fixes).

ACPICA: Fix wrong interpretation of PCC address (git-fixes).

ACPICA: Hardware: Do not flush CPU cache when entering S4 and S5
 (git-fixes).

ACPICA: Utilities: Avoid deleting the same object twice in a row
 (git-fixes).

ACPICA: actypes.h: Expand the ACPI_ACCESS_ definitions (git-fixes).

ALSA: seq: Set upper limit of processed events (git-fixes).

ASoC: mediatek: mt8173: fix device_node leak (git-fixes).

Bluetooth: Fix debugfs entry leak in hci_register_dev() (git-fixes).

Documentation: fix firewire.rst ABI file path error (git-fixes).

HID: apple: Do not reset quirks when the Fn key is not found (git-fixes).

HID: quirks: Allow inverting the absolute X/Y values (git-fixes).

HID: uhid: Fix worker ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.40.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.40.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.40.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.40.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.40.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.40.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.40.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.40.1", rls:"SLES15.0SP3"))) {
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
