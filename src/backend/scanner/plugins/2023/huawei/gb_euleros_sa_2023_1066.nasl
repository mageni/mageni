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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1066");
  script_cve_id("CVE-2021-0920", "CVE-2021-20322", "CVE-2021-37159", "CVE-2021-3753", "CVE-2021-40490", "CVE-2021-4083", "CVE-2021-42008", "CVE-2021-42739", "CVE-2021-43389", "CVE-2021-43976");
  script_tag(name:"creation_date", value:"2023-01-09 15:11:01 +0000 (Mon, 09 Jan 2023)");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 18:36:00 +0000 (Tue, 12 Oct 2021)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-1066)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1066");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1066");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-1066 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.(CVE-2021-42008)

A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in the Linux kernel through 5.13.13.(CVE-2021-40490)

hso_free_net_device in drivers/net/usb/hso.c in the Linux kernel through 5.13.4 calls unregister_netdev without checking for the NETREG_REGISTERED state, leading to a use-after-free and a double free.(CVE-2021-37159)

A race problem was seen in the vt_k_ioctl in drivers/tty/vt/vt_ioctl.c in the Linux kernel, which may cause an out of bounds read in vt as the write access to vc_mode is not protected by lock-in vt_ioctl (KDSETMDE). The highest threat from this vulnerability is to data confidentiality.(CVE-2021-3753)

The firewire subsystem in the Linux kernel through 5.14.13 has a buffer overflow related to drivers/media/firewire/firedtv-avc.c and drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt mishandles bounds checking.(CVE-2021-42739)

An issue was discovered in the Linux kernel before 5.14.15. There is an array-index-out-of-bounds flaw in the detach_capi_ctr function in drivers/isdn/capi/kcapi.c.(CVE-2021-43389)

In the Linux kernel through 5.15.2, mwifiex_usb_recv in drivers/net/wireless/marvell/mwifiex/usb.c allows an attacker (who can connect a crafted USB device) to cause a denial of service (skb_over_panic).(CVE-2021-43976)

A flaw in the processing of received ICMP errors (ICMP fragment needed and ICMP redirect) in the Linux kernel functionality was found to allow the ability to quickly scan open UDP ports. This flaw allows an off-path remote user to effectively bypass the source port UDP randomization. The highest threat from this vulnerability is to confidentiality and possibly integrity, because software that relies on UDP source port randomization are indirectly affected as well.(CVE-2021-20322)

A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race condition. This flaw allows a local user to crash the system or escalate their privileges on the system. This flaw affects Linux kernel versions prior to 5.16-rc4.(CVE-2021-4083)

A vulnerability was found in unix_dgram_recvmsg in net/unix/af_unix.c in the Linux kernel's garbage collection for Unix domain socket file handlers. In this flaw, a missing cleanup may lead to a use-after-free due to a race problem. This flaw allows a local user to crash the system or escalate their privileges on the system.(CVE-2021-0920)");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_91", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_91", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_91", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_91", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_91", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_91", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_91", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_91", rls:"EULEROSVIRT-3.0.2.6"))) {
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
