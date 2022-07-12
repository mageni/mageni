# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.883019");
  script_version("2019-09-05T05:22:48+0000");
  script_cve_id("CVE-2018-9568", "CVE-2018-17972", "CVE-2018-18445");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-05 05:22:48 +0000 (Thu, 05 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-03-21 09:50:26 +0100 (Thu, 21 Mar 2019)");
  script_name("CentOS Update for kernel CESA-2019:0512 centos7 ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-March/023218.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the CESA-2019:0512 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: Memory corruption due to incorrect socket cloning (CVE-2018-9568)

  * kernel: Unprivileged users able to inspect kernel stacks of arbitrary
tasks (CVE-2018-17972)

  * kernel: Faulty computation of numeric bounds in the BPF verifier
(CVE-2018-18445)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es) and Enhancement(s):

  * kernel fuse invalidates cached attributes during reads (BZ#1657921)

  * [NetApp-FC-NVMe] RHEL7.6: nvme reset gets hung indefinitely (BZ#1659937)

  * Memory reclaim deadlock calling __sock_create() after
memalloc_noio_save() (BZ#1660392)

  * hardened usercopy is causing crash (BZ#1660815)

  * Backport: xfrm: policy: init locks early (BZ#1660887)

  * AWS m5 instance type loses NVMe mounted volumes [was: Unable to Mount
StatefulSet PV in AWS EBS] (BZ#1661947)

  * RHEL 7.6 running on a VirtualBox guest with a GUI has a mouse problem
(BZ#1662848)

  * Kernel bug report in cgroups on heavily contested 3.10 node (BZ#1663114)

  * [PCIe] SHPC probe crash on Non-ACPI/Non-SHPC ports (BZ#1663241)

  * [Cavium 7.7 Feat] qla2xxx: Update to latest upstream. (BZ#1663508)

  * Regression in lpfc and the CNE1000 (BE2 FCoE) adapters that no longer
initialize (BZ#1664067)

  * [csiostor] call trace after command: modprobe csiostor (BZ#1665370)

  * libceph: fall back to sendmsg for slab pages (BZ#1665814)

  * Deadlock between stop_one_cpu_nowait() and stop_two_cpus() (BZ#1667328)

  * Soft lockups occur when the sd driver passes a device size of 1 sector to
string_get_size() (BZ#1667989)

  * [RHEL7.7] BUG: unable to handle kernel paging request at ffffffffffffffff
(BZ#1668208)

  * RHEL7.6 - powerpc/pseries: Disable CPU hotplug across migrations /
powerpc/rtas: Fix a potential race between CPU-Offline &amp  Migration (LPM)
(BZ#1669044)

  * blk-mq: fix corruption with direct issue (BZ#1670511)

  * [RHEL7][patch] iscsi driver can block reboot/shutdown (BZ#1670680)

  * [DELL EMC 7.6 BUG] Unable to create-namespace over Dell NVDIMM-N
(BZ#1671743)

  * efi_bgrt_init fails to ioremap error during boot (BZ#1671745)

  * Unable to mount a share on kernel- 3.10.0-957.el7. The share can be
mounted on kernel-3.10.0-862.14.4.el7 (BZ#1672448)

  * System crash with RIP nfs_readpage_async+0x43 -- BUG: unable to handle
kernel NULL pointer dereference (BZ#1672510)

Users of kernel are advised to upgrade to these updated packages, which fix
these bugs and add this enhancement.");

  script_tag(name:"affected", value:"'kernel' package(s) on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if((res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~957.10.1.el7", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if(__pkg_match) exit(99);
  exit(0);
}
