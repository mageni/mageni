# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883191");
  script_version("2020-02-28T12:26:57+0000");
  script_cve_id("CVE-2019-14816", "CVE-2019-14895", "CVE-2019-14898", "CVE-2019-14901", "CVE-2019-17133", "CVE-2019-11599");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-02 09:46:02 +0000 (Mon, 02 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-02-27 04:00:37 +0000 (Thu, 27 Feb 2020)");
  script_name("CentOS: Security Advisory for bpftool (CESA-2020:0374)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-February/035645.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2020:0374 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: heap overflow in mwifiex_update_vs_ie() function of Marvell WiFi
driver (CVE-2019-14816)

  * kernel: heap-based buffer overflow in mwifiex_process_country_ie()
function in drivers/net/wireless/marvell/mwifiex/sta_ioctl.c
(CVE-2019-14895)

  * kernel: heap overflow in marvell/mwifiex/tdls.c (CVE-2019-14901)

  * kernel: buffer overflow in cfg80211_mgd_wext_giwessid in
net/wireless/wext-sme.c (CVE-2019-17133)

  * kernel: incomplete fix  for race condition between
mmget_not_zero()/get_task_mm() and core dumping in CVE-2019-11599
(CVE-2019-14898)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * [Azure][7.8] Include patch 'PCI: hv: Avoid use of hv_pci_dev->pci_slot
after freeing it' (BZ#1766089)

  * [Hyper-V][RHEL7.8] When accelerated networking is enabled on RedHat,
network interface(eth0) moved to new network namespace does not obtain IP
address. (BZ#1766093)

  * [Azure][RHEL 7.6] hv_vmbus probe pass-through GPU card failed
(BZ#1766097)

  * SMB3: Do not error out on large file transfers if server responds with
STATUS_INSUFFICIENT_RESOURCES (BZ#1767621)

  * Since RHEL commit 5330f5d09820 high load can cause dm-multipath path
failures (BZ#1770113)

  * Hard lockup in free_one_page()->_raw_spin_lock() because sosreport
command is reading from /proc/pagetypeinfo (BZ#1770732)

  * patchset for x86/atomic: Fix smp_mb__{before, after}_atomic() (BZ#1772812)

  * fix compat statfs64() returning EOVERFLOW for when _FILE_OFFSET_BITS=64
(BZ#1775678)

  * Guest crash after load cpuidle-haltpoll driver (BZ#1776289)

  * RHEL 7.7 long I/O stalls with bnx2fc from not masking off scope bits of
retry delay value (BZ#1776290)

  * Multiple 'mv' processes hung on a gfs2 filesystem (BZ#1777297)

  * Moving Egress IP will result in conntrack sessions being DESTROYED
(BZ#1779564)

  * core: backports from upstream (BZ#1780033)

  * kernel BUG at arch/powerpc/platforms/pseries/lpar.c:482! (BZ#1780148)

  * Race between tty_open() and flush_to_ldisc()  using the
tty_struct->driver_data field. (BZ#1780163)");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1062.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1062.12.1.el7.centos.plus", rls:"CentOS7"))) {
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