# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0416.1");
  script_cve_id("CVE-2017-13695", "CVE-2018-7755", "CVE-2019-3837", "CVE-2019-3900", "CVE-2020-15393", "CVE-2020-16119", "CVE-2020-36557", "CVE-2020-36558", "CVE-2021-26341", "CVE-2021-33655", "CVE-2021-33656", "CVE-2021-34981", "CVE-2021-39713", "CVE-2021-45868", "CVE-2022-1011", "CVE-2022-1048", "CVE-2022-1353", "CVE-2022-1462", "CVE-2022-1652", "CVE-2022-1679", "CVE-2022-20132", "CVE-2022-20166", "CVE-2022-20368", "CVE-2022-20369", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166", "CVE-2022-21180", "CVE-2022-21385", "CVE-2022-21499", "CVE-2022-2318", "CVE-2022-2663", "CVE-2022-28356", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-3028", "CVE-2022-3303", "CVE-2022-33981", "CVE-2022-3424", "CVE-2022-3524", "CVE-2022-3565", "CVE-2022-3566", "CVE-2022-3586", "CVE-2022-3621", "CVE-2022-3635", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-36879", "CVE-2022-36946", "CVE-2022-3903", "CVE-2022-39188", "CVE-2022-40768", "CVE-2022-4095", "CVE-2022-41218", "CVE-2022-41848", "CVE-2022-41850", "CVE-2022-41858", "CVE-2022-43750", "CVE-2022-44032", "CVE-2022-44033", "CVE-2022-45934");
  script_tag(name:"creation_date", value:"2023-02-16 04:21:52 +0000 (Thu, 16 Feb 2023)");
  script_version("2023-02-16T10:08:32+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:08:32 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-01 19:46:00 +0000 (Thu, 01 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0416-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0416-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230416-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0416-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2017-13695: Fixed fix acpi operand cache leak in nseval.c
 (bsc#1055710).

CVE-2018-7755: Fixed bypass of kernel security protections such as KASLR
 using fd_locked_ioctl function in drivers/block/floppy.c (bnc#1084513).

CVE-2019-3837: Fixed memory leak due to thread-unsafe implementation of
 the net_dma code in tcp_recvmsg() (bnc#1131430).

CVE-2019-3900: Fixed infinite loop while receiving packets in vhost_net
 (bnc#1133374).

CVE-2020-15393: Fixed memory leak in usbtest_disconnect in
 drivers/usb/misc/usbtest.c (bnc#1173514).

CVE-2020-16119: Fixed use-after-free exploitable by a local attacker due
 to reuse of a DCCP socket (bnc#1177471).

CVE-2020-36557: Fixed race condition in the VT_DISALLOCATE ioctl and
 closing/opening of ttys which could lead to a use-after-free
 (bnc#1201429).

CVE-2020-36558: Fixed race condition in VT_RESIZEX (bsc#1200910).

CVE-2021-26341: Fixed vulnerablity where some AMD CPUs may transiently
 execute beyond unconditional direct branches, which may potentially
 result in data leakage (bnc#1201050).

CVE-2021-33655: When sending malicous data to kernel by ioctl cmd
 FBIOPUT_VSCREENINFO,kernel will write memory out of bounds (bnc#1201635).

CVE-2021-33656: Fixed memory out of bounds write when setting font with
 malicous data by ioctl cmd PIO_FONT (bnc#1201636).

CVE-2021-34981: Fixed file refcounter in bluetooth cmtp when
 cmtp_attach_device fails (bsc#1191961).

CVE-2021-39713: Fixed race condition in the network scheduling subsystem
 which could lead to a use-after-free (bsc#1196973).

CVE-2021-45868: Fixed use-after-free in fs/quota/quota_tree.c
 (bnc#1197366).

CVE-2022-1011: Fixed UAF reads of write() buffers, allowing theft of
 (partial) /etc/shadow hashes (bsc#1197343).

CVE-2022-1048: Fixed potential AB/BA lock with buffer_mutex and
 mmap_lock (bsc#1197331).

CVE-2022-1353: Fixed denial of service in the pfkey_register function in
 net/key/af_key.c (bnc#1198516).

CVE-2022-1462: Fixed out-of-bounds read in the TeleTYpe subsystem
 allowing local user to crash the system or read unauthorized random data
 from memory (bnc#1198829).

CVE-2022-1652: Fixed use after free in floppy (bsc#1199063).

CVE-2022-1679: Fixed use-after-free in the atheros wireless adapter
 driver (bnc#1199487).

CVE-2022-20132: Fixed out of bounds read in lg_probe and related
 functions of hid-lg.c and other USB HID files (bnc#1200619).

CVE-2022-20166: Fixed out of bounds write due to a heap buffer overflow
 which could lead to local escalation of privilege with System execution
 privileges needed (bnc#1200598).

CVE-2022-20368: Fixed slab-out-of-bounds access in packet_recvmsg()
 (bnc#1202346).

CVE-2022-20369: Fixed out of bounds write due to improper input
 validation in v4l2_m2m_querybuf of v4l2-mem2mem.c ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.138.1", rls:"SLES11.0SP4"))) {
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
