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
  script_oid("1.3.6.1.4.1.25623.1.0.883377");
  script_version("2021-09-03T10:01:28+0000");
  script_cve_id("CVE-2020-27777", "CVE-2021-22555", "CVE-2021-29154", "CVE-2021-29650", "CVE-2021-32399");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-09-03 12:13:43 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-22 17:18:00 +0000 (Tue, 22 Dec 2020)");
  script_tag(name:"creation_date", value:"2021-09-02 01:01:07 +0000 (Thu, 02 Sep 2021)");
  script_name("CentOS: Security Advisory for bpftool (CESA-2021:3327)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:3327");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-August/048356.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2021:3327 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: out-of-bounds write in xt_compat_target_from_user() in
net/netfilter/x_tables.c (CVE-2021-22555)

  * kernel: race condition for removal of the HCI controller (CVE-2021-32399)

  * kernel: powerpc: RTAS calls can be used to compromise kernel integrity
(CVE-2020-27777)

  * kernel: Local privilege escalation due to incorrect BPF JIT branch
displacement computation (CVE-2021-29154)

  * kernel: lack a full memory barrier upon the assignment of a new table
value in net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h
may lead to DoS (CVE-2021-29650)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * SAN Switch rebooted and caused (?) OpenStack compute node to reboot
(BZ#1897576)

  * sysfs: cannot create duplicate filename '/class/mdio_bus/ixgbe-8100
(BZ#1915449)

  * XFS: read-only recovery does not update free space accounting in
superblock (BZ#1921551)

  * The memcg_params field of kmem_cache struct contains an old slab address
that is to small for the current size of memcg_limited_groups_array_size.
(BZ#1951810)

  * Backport of upstream patch 'net: Update window_clamp if SOCK_RCVBUF is
set ' into rhel-7 (BZ#1962196)

  * Kernel panic in init_cq_frag_buf (BZ#1962499)

  * futex: futex_requeue can potentially free the pi_state structure twice
(BZ#1966856)

  * be_poll lockup doing ifenslave when netconsole using bond (BZ#1971744)

  * OCP4.7 nodes panic at BUG_ON in nf_nat_setup_info() (BZ#1972970)");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1160.41.1.el7", rls:"CentOS7"))) {
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