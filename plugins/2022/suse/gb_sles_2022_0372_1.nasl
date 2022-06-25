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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0372.1");
  script_cve_id("CVE-2020-28097", "CVE-2021-3564", "CVE-2021-39648", "CVE-2021-39657", "CVE-2021-4083", "CVE-2021-4135", "CVE-2021-4159", "CVE-2021-4197", "CVE-2021-4202", "CVE-2021-44733", "CVE-2022-0322", "CVE-2022-0330", "CVE-2022-0435", "CVE-2022-22942");
  script_tag(name:"creation_date", value:"2022-02-12 03:22:52 +0000 (Sat, 12 Feb 2022)");
  script_version("2022-02-14T11:39:42+0000");
  script_tag(name:"last_modification", value:"2022-02-15 11:09:28 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-25 18:08:00 +0000 (Tue, 25 Jan 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0372-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0372-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220372-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0372-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-0435: Fixed remote stack overflow in net/tipc module that
 validate domain record count on input (bsc#1195254).

CVE-2021-3564: Fixed double-free memory corruption in the Linux kernel
 HCI device initialization subsystem that could have been used by
 attaching malicious HCI TTY Bluetooth devices. A local user could use
 this flaw to crash the system (bnc#1186207).

CVE-2020-28097: Fixed out-of-bounds read in vgacon subsystem that
 mishandled software scrollback (bnc#1187723).

CVE-2021-44733: Fixed a use-after-free exists in drivers/tee/tee_shm.c
 in the TEE subsystem, that could have occurred because of a race
 condition in tee_shm_get_from_id during an attempt to free a shared
 memory object (bnc#1193767).

CVE-2022-0322: Fixed SCTP issue with account stream padding length for
 reconf chunk (bsc#1194985).

CVE-2021-4135: Fixed zero-initialize memory inside netdevsim for new
 map's value in function nsim_bpf_map_alloc (bsc#1193927).

CVE-2022-22942: Fixed stale file descriptors on failed usercopy
 (bsc#1195065).

CVE-2021-39657: Fixed out of bounds read due to a missing bounds check
 in ufshcd_eh_device_reset_handler of ufshcd.c. This could lead to local
 information disclosure with System execution privileges needed
 (bnc#1193864).

CVE-2021-39648: Fixed possible disclosure of kernel heap memory due to a
 race condition in gadget_dev_desc_UDC_show of configfs.c. This could
 lead to local information disclosure with System execution privileges
 needed. User interaction is not needed for exploitation (bnc#1193861).

CVE-2022-0330: Fixed flush TLBs before releasing backing store
 (bsc#1194880).

CVE-2021-4197: Use cgroup open-time credentials for process migraton
 perm checks (bsc#1194302).

CVE-2021-4202: Fixed NFC race condition by adding NCI_UNREG flag
 (bsc#1194529).

CVE-2021-4083: Fixed a read-after-free memory flaw inside the garbage
 collection for Unix domain socket file handlers when users call close()
 and fget() simultaneouslyand can potentially trigger a race condition
 (bnc#1193727).

CVE-2021-4159: Fixed kernel ptr leak vulnerability via BPF in
 coerce_reg_to_size (bsc#1194227).


The following non-security bugs were fixed:

KVM: remember position in kvm->vcpus array (bsc#1190973).

KVM: s390: index kvm->arch.idle_mask by vcpu_idx (bsc#1190973).

SUNRPC: Add basic load balancing to the transport switch - kabi fix.
 (bnc#1192729).

SUNRPC: Add basic load balancing to the transport switch. (bnc#1192729)

SUNRPC: Fix initialisation of struct rpc_xprt_switch (bnc#1192729).

SUNRPC: Optimise transport balancing code (bnc#1192729).

SUNRPC: Replace division by multiplication in calculation of queue
 length (bnc#1192729).

SUNRPC: Skip zero-refcount transports (bnc#1192729).

USB: serial: option: add Telit FN990 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.88.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.88.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.88.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.88.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.88.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.88.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.88.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.88.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.88.1", rls:"SLES12.0SP5"))) {
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
