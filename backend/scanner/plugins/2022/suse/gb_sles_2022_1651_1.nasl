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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1651.1");
  script_cve_id("CVE-2018-7755", "CVE-2019-20811", "CVE-2021-20292", "CVE-2021-20321", "CVE-2021-38208", "CVE-2021-43389", "CVE-2022-1011", "CVE-2022-1280", "CVE-2022-1353", "CVE-2022-1419", "CVE-2022-1516", "CVE-2022-23960", "CVE-2022-28748");
  script_tag(name:"creation_date", value:"2022-05-13 04:52:19 +0000 (Fri, 13 May 2022)");
  script_version("2022-05-16T06:44:58+0000");
  script_tag(name:"last_modification", value:"2022-05-16 06:44:58 +0000 (Mon, 16 May 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-24 14:34:00 +0000 (Thu, 24 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1651-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1651-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221651-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:1651-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2018-7755: Fixed an issue in the fd_locked_ioctl function in
 drivers/block/floppy.c. The floppy driver will copy a kernel pointer to
 user memory in response to the FDGETPRM ioctl. An attacker can send the
 FDGETPRM ioctl and use the obtained kernel pointer to discover the
 location of kernel code and data and bypass kernel security protections
 such as KASLR (bnc#1084513).

CVE-2019-20811: Fixed issue in rx_queue_add_kobject() and
 netdev_queue_add_kobject() in net/core/net-sysfs.c, where a reference
 count is mishandled (bnc#1172456).

CVE-2021-20292: Fixed object validation prior to performing operations
 on the object in nouveau_sgdma_create_ttm in Nouveau DRM subsystem
 (bnc#1183723).

CVE-2021-20321: Fixed a race condition accessing file object in the
 OverlayFS subsystem in the way users do rename in specific way with
 OverlayFS. A local user could have used this flaw to crash the system
 (bnc#1191647).

CVE-2021-38208: Fixed a denial of service (NULL pointer dereference and
 BUG) by making a getsockname call after a certain type of failure of a
 bind call (bnc#1187055).

CVE-2021-43389: Fixed an array-index-out-of-bounds flaw in the
 detach_capi_ctr function in drivers/isdn/capi/kcapi.c (bnc#1191958).

CVE-2022-1011: Fixed a use-after-free flaw inside the FUSE filesystem in
 the way a user triggers write(). This flaw allowed a local user to gain
 unauthorized access to data from the FUSE filesystem, resulting in
 privilege escalation (bnc#1197343).

CVE-2022-1280: Fixed a use-after-free vulnerability in drm_lease_held in
 drivers/gpu/drm/drm_lease.c (bnc#1197914).

CVE-2022-1353: Fixed access control to kernel memory in the
 pfkey_register function in net/key/af_key.c (bnc#1198516).

CVE-2022-1419: Fixed a concurrency use-after-free in
 vgem_gem_dumb_create (bsc#1198742).

CVE-2022-1516: Fixed null-ptr-deref caused by x25_disconnect
 (bsc#1199012).

CVE-2022-23960: Fixed speculation issues in the Branch History Buffer
 that allowed an attacker to obtain sensitive information using cache
 allocation (bnc#1196657).

CVE-2022-28748: Fixed memory lead over the network by ax88179_178a
 devices (bsc#1196018).

The following non-security bugs were fixed:

IB/qib: Fix memory leak in qib_user_sdma_queue_pkts() (git-fixes)

NFSD: prevent underflow in nfssvc_decode_writeargs() (git-fixes).

NFSv4: recover from pre-mature loss of openstateid (bsc#1196247).

NFSv4: Do not try to CLOSE if the stateid 'other' field has changed
 (bsc#1196247).

NFSv4: Fix a regression in nfs_set_open_stateid_locked() (bsc#1196247).

NFSv4: Handle NFS4ERR_OLD_STATEID in CLOSE/OPEN_DOWNGRADE (bsc#1196247).

NFSv4: Wait for stateid updates after CLOSE/OPEN_DOWNGRADE (bsc#1196247).

NFSv4: fix open failure with O_ACCMODE flag (git-fixes).

PCI/switchtec: Read ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.97.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.97.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.97.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.97.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.97.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.97.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.97.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.97.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.97.1", rls:"SLES12.0SP5"))) {
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
