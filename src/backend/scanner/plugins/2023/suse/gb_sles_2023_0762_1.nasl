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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0762.1");
  script_cve_id("CVE-2022-38096", "CVE-2022-4129", "CVE-2023-0597", "CVE-2023-1118", "CVE-2023-23559", "CVE-2023-26545");
  script_tag(name:"creation_date", value:"2023-03-28 13:04:06 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-29T10:10:12+0000");
  script_tag(name:"last_modification", value:"2023-03-29 10:10:12 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 19:26:00 +0000 (Fri, 03 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0762-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0762-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230762-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0762-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2022-38096: Fixed NULL-ptr deref in vmw_cmd_dx_define_query() (bsc#1203331).
CVE-2022-4129: Fixed a denial of service with the Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing sk_user_data can lead to a race condition and NULL pointer dereference. (bsc#1205711)
CVE-2023-0597: Fixed lack of randomization of per-cpu entry area in x86/mm (bsc#1207845).
CVE-2023-1118: Fixed a use-after-free bugs caused by ene_tx_irqsim() in media/rc (bsc#1208837).
CVE-2023-23559: Fixed integer overflow in rndis_wlan that leads to a buffer overflow (bsc#1207051).
CVE-2023-26545: Fixed double free in net/mpls/af_mpls.c upon an allocation failure (bsc#1208700).

The following non-security bugs were fixed:

bonding: fix 802.3ad state sent to partner when unbinding slave (git-fixes).
do not sign the vanilla kernel (bsc#1209008).
icmp: do not fail on fragment reassembly time exceeded (git-fixes).
ipmi: fix initialization when workqueue allocation fails (git-fixes).
ipmi: msghandler: Make symbol 'remove_work_wq' static (git-fixes).
kabi fix for - SUNRPC: Fix priority queue fairness (git-fixes).
kabi fix for: NFS: Pass error information to the pgio error cleanup routine (git-fixes).
kabi/severities: add l2tp local symbols kernel-module-subpackage: Fix expansion with -b parameter (bsc#1208179). When -b is specified the script is prefixed with KMP_NEEDS_MKINITRD=1 which sets the variable for a simple command. However, the script is no longer a simple command. Export the variable instead.
media: coda: Add check for dcoda_iram_alloc (git-fixes).
media: coda: Add check for kmalloc (git-fixes).
media: platform: ti: Add missing check for devm_regulator_get (git-fixes).
net: aquantia: fix RSS table and key sizes (git-fixes).
netfilter: ipvs: Fix inappropriate output of procfs (git-fixes).
netfilter: xt_connlimit: do not store address in the conn nodes (git-fixes).
nfs: Fix nfsi->nrequests count error on nfs_inode_remove_request (git-fixes).
nfs: Pass error information to the pgio error cleanup routine (git-fixes).
nfsd: fix handling of readdir in v4root vs. mount upcall timeout (git-fixes).
nfsd: fix race to check ls_layouts (git-fixes).
nfsd: under NFSv4.1, fix double svc_xprt_put on rpc_create failure (git-fixes).
ocfs2: Fix data corruption after failed write (bsc#1208542).
pNFS/filelayout: Fix coalescing test for single DS (git-fixes).
powerpc/eeh: Fix use-after-release of EEH driver (bsc#1065729).
powerpc/fscr: Enable interrupts earlier before calling get_user() (bsc#1065729).
powerpc/powernv: Fix build error in opal-imc.c when NUMA=n (bsc#1065729).
powerpc/powernv: IMC fix out of bounds memory access at shutdown (bsc#1065729).
scsi: qla2xxx: Add option to disable FC2 Target support (bsc#1198438 bsc#1206103).
sunrpc: Fix priority queue fairness ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.127.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.127.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.127.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.127.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.127.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.127.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.127.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.127.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.127.1", rls:"SLES12.0SP5"))) {
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
