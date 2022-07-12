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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1163.1");
  script_cve_id("CVE-2021-39698", "CVE-2021-45402", "CVE-2021-45868", "CVE-2022-0850", "CVE-2022-0854", "CVE-2022-1011", "CVE-2022-1016", "CVE-2022-1048", "CVE-2022-1055", "CVE-2022-1195", "CVE-2022-1198", "CVE-2022-1199", "CVE-2022-1205", "CVE-2022-23036", "CVE-2022-23037", "CVE-2022-23038", "CVE-2022-23039", "CVE-2022-23040", "CVE-2022-23041", "CVE-2022-23042", "CVE-2022-27223", "CVE-2022-27666", "CVE-2022-28388", "CVE-2022-28389", "CVE-2022-28390");
  script_tag(name:"creation_date", value:"2022-04-13 06:20:10 +0000 (Wed, 13 Apr 2022)");
  script_version("2022-04-13T06:20:10+0000");
  script_tag(name:"last_modification", value:"2022-04-13 10:28:29 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-23 17:21:00 +0000 (Wed, 23 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1163-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1163-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221163-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:1163-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-0854: Fixed a memory leak flaw was found in the Linux kernels
 DMA subsystem. This flaw allowed a local user to read random memory from
 the kernel space. (bnc#1196823)

CVE-2022-1016: Fixed a vulnerability in the nf_tables component of the
 netfilter subsystem. This vulnerability gives an attacker a powerful
 primitive that can be used to both read from and write to relative stack
 data, which can lead to arbitrary code execution. (bsc#1197227)

CVE-2022-1199: Fixed null-ptr-deref and use-after-free vulnerabilities
 that allow an attacker to crash the linux kernel by simulating Amateur
 Radio. (bsc#1198028)

CVE-2022-1205: Fixed null pointer dereference and use-after-free
 vulnerabilities that allow an attacker to crash the linux kernel by
 simulating Amateur Radio. (bsc#1198027)

CVE-2022-1198: Fixed an use-after-free vulnerability that allow an
 attacker to crash the linux kernel by simulating Amateur Radio
 (bsc#1198030).

CVE-2022-1195: Fixed an use-after-free vulnerability which could allow a
 local attacker with a user privilege to execute a denial of service.
 (bsc#1198029)

CVE-2022-28389: Fixed a double free in drivers/net/can/usb/mcba_usb.c
 vulnerability in the Linux kernel. (bnc#1198033)

CVE-2022-28388: Fixed a double free in drivers/net/can/usb/usb_8dev.c
 vulnerability in the Linux kernel. (bnc#1198032)

CVE-2022-28390: Fixed a double free in drivers/net/can/usb/ems_usb.c
 vulnerability in the Linux kernel. (bnc#1198031)

CVE-2022-1048: Fixed a race Condition in snd_pcm_hw_free leading to
 use-after-free due to the AB/BA lock with buffer_mutex and mmap_lock.
 (bsc#1197331)

CVE-2022-1055: Fixed a use-after-free in tc_new_tfilter that could allow
 a local attacker to gain privilege escalation. (bnc#1197702)

CVE-2022-0850: Fixed a kernel information leak vulnerability in
 iov_iter.c. (bsc#1196761)

CVE-2022-27666: Fixed a buffer overflow vulnerability in IPsec ESP
 transformation code. This flaw allowed a local attacker with a normal
 user privilege to overwrite kernel heap objects and may cause a local
 privilege escalation. (bnc#1197462)

CVE-2021-45868: Fixed a wrong validation check in fs/quota/quota_tree.c
 which could lead to an use-after-free if there is a corrupted quota
 file. (bnc#1197366)

CVE-2022-1011: Fixed an use-after-free vulnerability which could allow a
 local attacker to retireve (partial) /etc/shadow hashes or any other
 data from filesystem when he can mount a FUSE filesystems. (bnc#1197343)

CVE-2022-27223: Fixed an out-of-array access in
 /usb/gadget/udc/udc-xilinx.c. (bsc#1197245)

CVE-2021-39698: Fixed a possible memory corruption due to a use after
 free in aio_poll_complete_work. This could lead to local escalation of
 privilege with no additional execution privileges needed. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.53.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.53.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.53.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.53.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.53.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.53.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.53.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.53.1", rls:"SLES15.0SP3"))) {
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
