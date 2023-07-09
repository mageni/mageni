# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2507.1");
  script_cve_id("CVE-2022-3566", "CVE-2022-45884", "CVE-2022-45885", "CVE-2022-45886", "CVE-2022-45887", "CVE-2022-45919", "CVE-2023-1380", "CVE-2023-2176", "CVE-2023-2194", "CVE-2023-2269", "CVE-2023-2513", "CVE-2023-28466", "CVE-2023-31084", "CVE-2023-31436", "CVE-2023-32269");
  script_tag(name:"creation_date", value:"2023-06-15 04:21:58 +0000 (Thu, 15 Jun 2023)");
  script_version("2023-06-20T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:26 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-05 17:24:00 +0000 (Fri, 05 May 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2507-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2507-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232507-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2507-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 AZURE kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-2269: Fixed a denial-of-service problem due to a possible recursive locking scenario, resulting in a deadlock in table_clear in drivers/md/dm-ioctl.c (bsc#1210806).
CVE-2022-3566: Fixed race condition in the TCP Handler (bsc#1204405).
CVE-2022-45886: Fixed a .disconnect versus dvb_device_open race condition in dvb_net.c that lead to a use-after-free (bsc#1205760).
CVE-2022-45885: Fixed a race condition in dvb_frontend.c that could cause a use-after-free when a device is disconnected (bsc#1205758).
CVE-2022-45887: Fixed a memory leak in ttusb_dec.c caused by the lack of a dvb_frontend_detach call (bsc#1205762).
CVE-2022-45919: Fixed a use-after-free in dvb_ca_en50221.c that could occur if there is a disconnect after an open, because of the lack of a wait_event (bsc#1205803).
CVE-2022-45884: Fixed a use-after-free in dvbdev.c, related to dvb_register_device dynamically allocating fops (bsc#1205756).
CVE-2023-31084: Fixed a blocking issue in drivers/media/dvb-core/dvb_frontend.c (bsc#1210783).
CVE-2023-31436: Fixed an out-of-bounds write in qfq_change_class() because lmax can exceed QFQ_MIN_LMAX (bsc#1210940).
CVE-2023-2194: Fixed an out-of-bounds write vulnerability in the SLIMpro I2C device driver (bsc#1210715).
CVE-2023-32269: Fixed a use-after-free in af_netrom.c, related to the fact that accept() was also allowed for a successfully connected AF_NETROM socket (bsc#1211186).
CVE-2023-28466: Fixed race condition that could lead to use-after-free or NULL pointer dereference in do_tls_getsockopt in net/tls/tls_main.c (bsc#1209366).
CVE-2023-1380: Fixed a slab-out-of-bound read problem in brcmf_get_assoc_ies() (bsc#1209287).
CVE-2023-2513: Fixed a use-after-free vulnerability in the ext4 filesystem (bsc#1211105).
CVE-2023-2176: Fixed an out-of-boundary read in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA (bsc#1210629).

The following non-security bugs were fixed:

ACPI: processor: Fix evaluating _PDC method when running as Xen dom0 (git-fixes).
Documentation: Document sysfs interfaces purr, spurr, idle_purr, idle_spurr (PED-3947 bsc#1210544 ltc#202303).
Drivers: hv: vmbus: Optimize vmbus_on_event (bsc#1211622).
Fix usrmerge error (boo#1211796)
IB/hfi1: Assign npages earlier (git-fixes)
IB/iser: bound protection_sg size by data_sg size (git-fixes)
IB/mlx4: Fix memory leaks (git-fixes)
IB/mlx4: Increase the timeout for CM cache (git-fixes)
IB/mlx5: Fix initializing CQ fragments buffer (git-fixes)
IB/rdmavt: Add __init/__exit annotations to module init/exit funcs (git-fixes)
IB/usnic: Fix potential deadlock (git-fixes)
KVM: nSVM: clear events pending from svm_complete_interrupts() when exiting to L1 (git-fixes).
KVM: x86: Update the exit_qualification access bits while walking an address (git-fixes).
KVM: x86: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.136.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.136.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.136.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.136.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.136.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.136.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.136.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.136.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.136.1", rls:"SLES12.0SP5"))) {
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
