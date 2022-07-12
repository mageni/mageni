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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0765.1");
  script_cve_id("CVE-2021-44879", "CVE-2021-45095", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0487", "CVE-2022-0492", "CVE-2022-0617", "CVE-2022-0644", "CVE-2022-24448", "CVE-2022-24959");
  script_tag(name:"creation_date", value:"2022-03-09 04:10:18 +0000 (Wed, 09 Mar 2022)");
  script_version("2022-03-09T08:30:28+0000");
  script_tag(name:"last_modification", value:"2022-03-09 11:12:38 +0000 (Wed, 09 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-22 18:26:00 +0000 (Tue, 22 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0765-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0765-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220765-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0765-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


Transient execution side-channel attacks attacking the Branch History Buffer (BHB), named 'Branch Target Injection' and 'Intra-Mode Branch History Injection' are now mitigated.

The following security bugs were fixed:

CVE-2022-0001: Fixed Branch History Injection vulnerability
 (bsc#1191580).

CVE-2022-0002: Fixed Intra-Mode Branch Target Injection vulnerability
 (bsc#1191580).

CVE-2022-0617: Fixed a null pointer dereference in UDF file system
 functionality. A local user could crash the system by triggering
 udf_file_write_iter() via a malicious UDF image. (bsc#1196079)

CVE-2022-0644: Fixed a denial of service by a local user. A assertion
 failure could be triggered in kernel_read_file_from_fd() (bsc#1196155).

CVE-2021-44879: In gc_data_segment() in fs/f2fs/gc.c, special files were
 not considered, which lead to a move_data_page NULL pointer dereference
 (bsc#1195987).

CVE-2022-24959: Fixed a memory leak in yam_siocdevprivate() in
 drivers/net/hamradio/yam.c (bsc#1195897).

CVE-2021-45095: Fixed refcount leak in pep_sock_accept in
 net/phonet/pep.c (bsc#1193867).

CVE-2022-0487: A use-after-free vulnerability was found in
 rtsx_usb_ms_drv_remove() in drivers/memstick/host/rtsx_usb_ms.c
 (bsc#1194516).

CVE-2022-0492: Fixed a privilege escalation related to cgroups v1
 release_agent feature, which allowed bypassing namespace isolation
 unexpectedly (bsc#1195543).

CVE-2022-24448: Fixed an issue in fs/nfs/dir.c. If an application sets
 the O_DIRECTORY flag, and tries to open a regular file,
 nfs_atomic_open() performs a regular lookup. If a regular file is found,
 ENOTDIR should have occurred, but the server instead returned
 uninitialized data in the file descriptor (bsc#1195612).

The following non-security bugs were fixed:

Bluetooth: bfusb: fix division by zero in send path (git-fixes).

Bluetooth: fix the erroneous flush_work() order (git-fixes).

EDAC/xgene: Fix deferred probing (bsc#1114648).

IB/rdmavt: Validate remote_addr during loopback atomic tests
 (bsc#1114685).

NFSv4.x: by default serialize open/close operations (bsc#1114893
 bsc#1195934). Make this work-around optional

NFSv42: Do not fail clone() unless the OP_CLONE operation failed
 (git-fixes).

NFSv42: Fix pagecache invalidation after COPY/CLONE (git-fixes).

NFSv4: Handle case where the lookup of a directory fails (git-fixes).

NFSv4: nfs_atomic_open() can race when looking up a non-regular file
 (git-fixes).

PCI: Add function 1 DMA alias quirk for Marvell 88SE9125 SATA controller
 (git-fixes).

RDMA/bnxt_re: Fix query SRQ failure (bsc#1050244).

RDMA/mlx5: Set user priority for DCT (bsc#1103991).

RDMA/netlink: Add __maybe_unused to static inline in C file
 (bsc#1046306).

Replace with an alternative fix for bsc#1185377

crypto: af_alg - get_page upon reassignment to TX SGL ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.91.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.91.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.91.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.91.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.91.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.91.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.91.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.91.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.91.1", rls:"SLES12.0SP5"))) {
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
