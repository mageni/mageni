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
  script_oid("1.3.6.1.4.1.25623.1.0.883263");
  script_version("2020-08-07T07:29:19+0000");
  script_cve_id("CVE-2019-19527", "CVE-2020-10757", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-10713");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-07 10:04:11 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-07-30 03:01:15 +0000 (Thu, 30 Jul 2020)");
  script_name("CentOS: Security Advisory for bpftool (CESA-2020:3220)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2020:3220");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-July/035780.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2020:3220 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: kernel: DAX hugepages not considered during mremap
(CVE-2020-10757)

  * kernel: buffer overflow in mwifiex_cmd_append_vsie_tlv function in
drivers/net/wireless/marvell/mwifiex/scan.c (CVE-2020-12653)

  * kernel: heap-based buffer overflow in mwifiex_ret_wmm_get_status function
in drivers/net/wireless/marvell/mwifiex/wmm.c (CVE-2020-12654)

  * kernel: use-after-free caused by a malicious USB device in the
drivers/hid/usbhid/hiddev.c driver (CVE-2019-19527)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * RHEL7.7 - scsi: ibmvfc: Avoid loss of all paths during SVC node reboot
(BZ#1830889)

  * [DELL EMC 7.8 BUG bnxt_en] Error messages related to hwrm observed for
BCM 57504 under dmesg in RHEL 7.8 (BZ#1834190)

  * kernel: provide infrastructure to support dual-signing of the kernel
(foundation to help address CVE-2020-10713) (BZ#1837429)

  * RHEL7.7 - Request: retrofit kernel commit f82b4b6 to RHEL 7.7/7.8 3.10
kernels. (BZ#1838602)

  * kipmi thread high CPU consumption when performing BMC firmware upgrade
(BZ#1841825)

  * RHEL7.7 - virtio-blk: fix hw_queue stopped on arbitrary error (kvm)
(BZ#1842994)

  * rhel 7 infinite blocked waiting on inode_dio_wait in nfs (BZ#1845520)

  * http request is taking more time for endpoint running on different host
via nodeport service (BZ#1847333)

  * ext4: change LRU to round-robin in extent status tree shrinker
(BZ#1847343)

  * libaio is returning duplicate events (BZ#1850055)

  * After upgrade to 3.9.89 pod containers with CPU limits fail to start due
to cgroup error (BZ#1850500)

  * Fix dpdk regression introduced by bz1837297 (BZ#1852245)");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1127.18.2.el7", rls:"CentOS7"))) {
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