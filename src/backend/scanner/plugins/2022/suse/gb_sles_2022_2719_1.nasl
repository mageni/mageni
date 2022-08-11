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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2719.1");
  script_cve_id("CVE-2020-36557", "CVE-2020-36558", "CVE-2021-33655", "CVE-2021-33656", "CVE-2022-1462", "CVE-2022-20166", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-08-10 04:21:08 +0000 (Wed, 10 Aug 2022)");
  script_version("2022-08-10T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-08-10 10:11:40 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 13:44:00 +0000 (Thu, 28 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2719-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2719-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222719-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2719-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-36557: Fixed race condition between the VT_DISALLOCATE ioctl
 and closing/opening of ttys that could lead to a use-after-free
 (bnc#1201429).

CVE-2020-36558: Fixed race condition involving VT_RESIZEX that could
 lead to a NULL pointer dereference and general protection fault
 (bnc#1200910).

CVE-2021-33655: Fixed out of bounds write with ioctl FBIOPUT_VSCREENINFO
 (bnc#1201635).

CVE-2021-33656: Fixed out of bounds write with ioctl PIO_FONT
 (bnc#1201636).

CVE-2022-1462: Fixed an out-of-bounds read flaw in the TeleTYpe
 subsystem (bnc#1198829).

CVE-2022-20166: Fixed possible out of bounds write due to sprintf
 unsafety that could cause local escalation of privilege (bnc#1200598).

CVE-2022-36946: Fixed incorrect packet truncation in nfqnl_mangle() that
 could lead to remote DoS (bnc#1201940).

The following non-security bugs were fixed:

Add missing recommends of kernel-install-tools to kernel-source-vanilla
 (bsc#1200442)

Bluetooth: hci_qca: Use del_timer_sync() before freeing (git-fixes).

Drop qla2xxx patch which prevented nvme port discovery (bsc#1200651
 bsc#1200644 bsc#1201954 bsc#1201958)

PCI: qcom: Fix runtime PM imbalance on probe errors (git-fixes).

arch_topology: Do not set llc_sibling if llc_id is invalid (git-fixes).

blk-cgroup: synchronize blkg creation against policy deactivation
 (git-fixes).

blk-zoned: allow BLKREPORTZONE without CAP_SYS_ADMIN (git-fixes).

blk-zoned: allow zone management send operations without CAP_SYS_ADMIN
 (git-fixes).

block: drbd: drbd_nl: Make conversion to 'enum drbd_ret_code' explicit
 (git-fixes).

bnxt_en: Re-write PCI BARs after PCI fatal error (git-fixes).

bnxt_en: Remove the setting of dev_port (git-fixes).

crypto: qat - disable registration of algorithms (git-fixes).

crypto: qat - fix memory leak in RSA (git-fixes).

crypto: qat - remove dma_free_coherent() for DH (git-fixes).

crypto: qat - remove dma_free_coherent() for RSA (git-fixes).

crypto: qat - set to zero DH parameters before free (git-fixes).

cxgb3/l2t: Fix undefined behaviour (git-fixes).

dm btree remove: fix use after free in rebalance_children() (git-fixes).

dm crypt: fix get_key_size compiler warning if !CONFIG_KEYS (git-fixes).

dm crypt: make printing of the key constant-time (git-fixes).

dm integrity: fix error code in dm_integrity_ctr() (git-fixes).

dm mirror log: round up region bitmap size to BITS_PER_LONG (git-fixes).

dm stats: add cond_resched when looping over entries (git-fixes).

dm: fix mempool NULL pointer race when completing IO (git-fixes).

do not call utsname() after ->nsproxy is NULL (bsc#1201196).

ehea: fix error return code in ehea_restart_qps() (git-fixes).

fsl_lpuart: Do not enable interrupts too early (git-fixes).

hex2bin: fix access beyond string end ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP5, SUSE Linux Enterprise Live Patching 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.130.1", rls:"SLES12.0SP5"))) {
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
