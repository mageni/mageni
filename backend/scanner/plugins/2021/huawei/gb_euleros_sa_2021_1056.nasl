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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1056");
  script_version("2021-01-08T23:22:45+0000");
  script_cve_id("CVE-2014-8181", "CVE-2018-14625", "CVE-2018-9363", "CVE-2019-0136", "CVE-2019-10126", "CVE-2019-10142", "CVE-2019-10639", "CVE-2019-11085", "CVE-2019-1125", "CVE-2019-11486", "CVE-2019-11599", "CVE-2019-12818", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14901", "CVE-2019-15099", "CVE-2019-15239", "CVE-2019-15292", "CVE-2019-15505", "CVE-2019-15917", "CVE-2019-15926", "CVE-2019-15927", "CVE-2019-16413", "CVE-2019-16746", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-18675", "CVE-2019-19060", "CVE-2019-19074", "CVE-2019-19078", "CVE-2019-19768", "CVE-2019-20636", "CVE-2019-3846", "CVE-2019-9500", "CVE-2019-9503", "CVE-2019-9506", "CVE-2020-0009", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10757", "CVE-2020-10942", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-12654", "CVE-2020-13974", "CVE-2020-15393", "CVE-2020-16166", "CVE-2020-24394", "CVE-2020-25211", "CVE-2020-25212", "CVE-2020-25643", "CVE-2020-7053", "CVE-2020-9383");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-01-12 11:05:42 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-08 21:55:14 +0000 (Fri, 08 Jan 2021)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2021-1056)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.2\.6");

  script_xref(name:"EulerOS-SA", value:"2021-1056");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1056");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2021-1056 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw that allowed an attacker to corrupt memory and possibly escalate privileges was found in the mwifiex kernel module while connecting to a malicious wireless network(CVE-2019-3846)

An issue was discovered in the Linux kernel before 5.6.1. drivers/media/usb/gspca/ov519.c allows NULL pointer dereferences in ov511_mode_init_regs and ov518_mode_init_regs when there are zero endpoints(CVE-2020-11608)

In the Linux kernel before 5.5.8, get_raw_socket in drivers/vhost/net.c lacks validation of an sk_family field, which might allow attackers to trigger kernel stack corruption via crafted system calls.(CVE-2020-10942)

An issue was discovered in the stv06xx subsystem in the Linux kernel before 5.6.1. drivers/media/usb/gspca/stv06xx/stv06xx.c and drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c mishandle invalid descriptors, as demonstrated by a NULL pointer dereference, aka CID-485b06aadb93.(CVE-2020-11609)

An out-of-bounds write flaw was found in the Linux kernel. A crafted keycode table could be used by drivers/input/input.c to perform the out-of-bounds write. A local user with root access can insert garbage to this keycode table that can lead to out-of-bounds memory access. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2019-20636)

The kernel in Red Hat Enterprise Linux 7 and MRG-2 does not clear garbage data for SG_IO buffer, which may leaking sensitive information to userspace.(CVE-2014-8181)

A flaw was found in the Linux kernels SELinux LSM hook implementation before version 5.7, where it incorrectly assumed that an skb would only contain a single netlink message. The hook would incorrectly only validate the first netlink message in the skb and allow or deny the rest of the messages within the skb with the granted permission without further processing.(CVE-2020-10751)

An information disclosure vulnerability exists when certain central processing units (CPU) speculatively access memory, aka 'Windows Kernel Information Disclosure Vulnerability'.(CVE-2019-1125)

A memory leak in the ath10k_usb_hif_tx_sg() function in drivers/net/wireless/ath/ath10k/usb.c in the Linux kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering usb_submit_urb() failures, aka CID-b8d17e7d93d2.(CVE-2019-19078)

A flaw was found in the Linux kernel's implementation of Userspace core dumps. This flaw allows an attacker with a local account to crash a trivial program and exfiltrate private kernel data.(CVE-2020-10732)

In the Linux kernel before 5.7.8, fs/nfsd/vfs.c (in the NFS ser ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.2.6.");

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

if(release == "EULEROSVIRT-3.0.2.6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_81.x86_64", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_81.x86_64", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_81.x86_64", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_81.x86_64", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_81.x86_64", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
