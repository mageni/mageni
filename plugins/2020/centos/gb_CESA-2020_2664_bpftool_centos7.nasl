# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883257");
  script_version("2020-06-30T06:18:22+0000");
  script_cve_id("CVE-2020-12888", "CVE-2020-0543");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-06-30 10:45:10 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-24 03:01:17 +0000 (Wed, 24 Jun 2020)");
  script_name("CentOS: Security Advisory for bpftool (CESA-2020:2664)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2020:2664");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-June/035769.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2020:2664 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * Kernel: vfio: access to disabled MMIO space of some devices may lead to
DoS scenario (CVE-2020-12888)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * kernel: hw: provide reporting and microcode mitigation toggle for
CVE-2020-0543 / Special Register Buffer Data Sampling (SRBDS) (BZ#1827187)

  * kernel BUG at fs/fscache/operation.c:70! FS-Cache: 4 == 5 is false -
current state is FSCACHE_OP_ST_COMPLETE but should be FSCACHE_OP_CANCELLED
in fscache_enqueue_operation (BZ#1839757)

  * Deadlock condition grabbing ssb_state lock (BZ#1841121)

1836244 - CVE-2020-12888 Kernel: vfio: access to disabled MMIO space of some devices may lead to DoS scenario

6. Package List:

Red Hat Enterprise Linux Client (v. 7):

Source:
kernel-3.10.0-1127.13.1.el7.src.rpm

noarch:
kernel-abi-whitelists-3.10.0-1127.13.1.el7.noarch.rpm
kernel-doc-3.10.0-1127.13.1.el7.noarch.rpm

x86_64:
bpftool-3.10.0-1127.13.1.el7.x86_64.rpm
bpftool-debuginfo-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-debug-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-debug-debuginfo-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-debug-devel-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-debuginfo-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-debuginfo-common-x86_64-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-devel-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-headers-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-tools-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-tools-debuginfo-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-tools-libs-3.10.0-1127.13.1.el7.x86_64.rpm
perf-3.10.0-1127.13.1.el7.x86_64.rpm
perf-debuginfo-3.10.0-1127.13.1.el7.x86_64.rpm
python-perf-3.10.0-1127.13.1.el7.x86_64.rpm
python-perf-debuginfo-3.10.0-1127.13.1.el7.x86_64.rpm

Red Hat Enterprise Linux Client Optional (v. 7):

x86_64:
bpftool-debuginfo-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-debug-debuginfo-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-debuginfo-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-debuginfo-common-x86_64-3.10.0-1127.13.1.el7.x86_64.rpm
kernel-tools-d ...

  Description truncated. Please see the references for more information.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1127.13.1.el7", rls:"CentOS7"))) {
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
