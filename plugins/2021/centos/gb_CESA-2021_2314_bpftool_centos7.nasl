# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883351");
  script_version("2021-06-17T06:11:17+0000");
  script_cve_id("CVE-2020-8648", "CVE-2020-12362", "CVE-2020-12363", "CVE-2020-12364", "CVE-2020-27170", "CVE-2021-3347");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-17 10:43:15 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-15 03:00:58 +0000 (Tue, 15 Jun 2021)");
  script_name("CentOS: Security Advisory for bpftool (CESA-2021:2314)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:2314");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-June/048337.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2021:2314 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: Integer overflow in Intel(R) Graphics Drivers (CVE-2020-12362)

  * kernel: Use after free via PI futex state (CVE-2021-3347)

  * kernel: use-after-free in n_tty_receive_buf_common function in
drivers/tty/n_tty.c (CVE-2020-8648)

  * kernel: Improper input validation in some Intel(R) Graphics Drivers
(CVE-2020-12363)

  * kernel: Null pointer dereference in some Intel(R) Graphics Drivers
(CVE-2020-12364)

  * kernel: Speculation on pointer arithmetic against bpf_context pointer
(CVE-2020-27170)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * kernel crash when call the timer function
(sctp_generate_proto_unreach_event) of sctp module (BZ#1707184)

  * SCSI error handling process on HP P440ar controller gets stuck
indefinitely in device reset operation (BZ#1830268)

  * netfilter: reproducible deadlock on nft_log module autoload (BZ#1858329)

  * netfilter: NULL pointer dereference in nf_tables_set_lookup()
(BZ#1873171)

  * [DELL EMC 7.9 Bug]: No acpi_pad threads on top command for 'power cap
policy equal to 0 watts' (BZ#1883174)

  * A race between i40e_ndo_set_vf_mac() and i40e_vsi_clear() in the i40e
driver causes a use after free condition of the kmalloc-4096 slab cache.
(BZ#1886003)

  * netxen driver performs poorly with RT kernel (BZ#1894274)

  * gendisk->disk_part_tbl->last_lookup retains pointer after partition
deletion (BZ#1898596)

  * Kernel experiences panic in update_group_power() due to division error
even with Bug 1701115 fix (BZ#1910763)

  * RHEL7.9 - zfcp: fix handling of FCP_RESID_OVER bit in fcp ingress path
(BZ#1917839)

  * RHEL7.9 - mm/THP: do not access vma->vm_mm after calling handle_userfault
(BZ#1917840)

  * raid: wrong raid io account (BZ#1927106)

  * qla2x00_status_cont_entry() missing upstream patch that prevents
unnecessary ABRT/warnings (BZ#1933784)

  * RHEL 7.9.z - System hang caused by workqueue stall in qla2xxx driver
(BZ#1937945)

  * selinux: setsebool can trigger a deadlock (BZ#1939091)

  * [Hyper-V][RHEL-7] Cannot boot kernel 3.10.0-1160.21.1.el7.x86_64 on
Hyper-V (BZ#1941841)");

  script_tag(name:"affected", value:"'bpftool' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1160.31.1.el7", rls:"CentOS7"))) {
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