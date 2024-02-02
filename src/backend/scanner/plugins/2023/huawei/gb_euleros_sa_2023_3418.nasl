# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3418");
  script_cve_id("CVE-2020-36516", "CVE-2022-36280", "CVE-2022-41858", "CVE-2022-45886", "CVE-2023-0458", "CVE-2023-1206", "CVE-2023-1513", "CVE-2023-2124", "CVE-2023-2176", "CVE-2023-2269", "CVE-2023-2513", "CVE-2023-30456", "CVE-2023-3106", "CVE-2023-3108", "CVE-2023-3141", "CVE-2023-31436", "CVE-2023-3159", "CVE-2023-3161", "CVE-2023-32269", "CVE-2023-3268", "CVE-2023-3358", "CVE-2023-34256", "CVE-2023-35001", "CVE-2023-35824", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3772", "CVE-2023-3776");
  script_tag(name:"creation_date", value:"2023-12-14 04:31:45 +0000 (Thu, 14 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:26:27 +0000 (Mon, 31 Jul 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-3418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3418");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3418");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-3418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in dm1105_remove in drivers/media/pci/dm1105/dm1105.c.(CVE-2023-35824)

A flaw was found in the Framebuffer Console (fbcon) in the Linux Kernel. When providing font->width and font->height greater than 32 to fbcon_set_font, since there are no checks in place, a shift-out-of-bounds occurs leading to undefined behavior and possible denial of service.(CVE-2023-3161)

A use-after-free flaw was found in r592_remove in drivers/memstick/host/r592.c in media access in the Linux Kernel. This flaw allows a local attacker to crash the system at device disconnect, possibly leading to a kernel information leak.(CVE-2023-3141)

A use after free issue was discovered in driver/firewire in outbound_phy_packet_callback in the Linux Kernel. In this flaw a local attacker with special privilege may cause a use after free problem when queue_event() fails.(CVE-2023-3159)

A use-after-free vulnerability was found in the Linux kernel's ext4 filesystem in the way it handled the extra inode size for extended attributes. This flaw could allow a privileged local user to cause a system crash or other undefined behaviors.(CVE-2023-2513)

A denial of service problem was found, due to a possible recursive locking scenario, resulting in a deadlock in table_clear in drivers/md/dm-ioctl.c in the Linux Kernel Device Mapper-Multipathing sub-component.(CVE-2023-2269)

A vulnerability was found in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA in the Linux Kernel. The improper cleanup results in out-of-boundary read, where a local user can utilize this problem to crash the system or escalation of privilege.(CVE-2023-2176)

** DISPUTED ** An issue was discovered in the Linux kernel before 6.3.3. There is an out-of-bounds read in crc16 in lib/crc16.c when called from fs/ext4/super.c because ext4_group_desc_csum does not properly check an offset. NOTE: this is disputed by third parties because the kernel is not intended to defend against attackers with the stated 'When modifying the block device while it is mounted by the filesystem' access.(CVE-2023-34256)

An out-of-bounds memory access flaw was found in the Linux kernel's XFS file system in how a user restores an XFS image after failure (with a dirty log journal). This flaw allows a local user to crash or potentially escalate their privileges on the system.(CVE-2023-2124)

An issue was discovered in the Linux kernel before 6.1.11. In net/netrom/af_netrom.c, there is a use-after-free because accept is also allowed for a successfully connected AF_NETROM socket. However, in order for an attacker to exploit this, the system must have netrom routing configured or the attacker must have the CAP_NET_ADMIN capability.(CVE-2023-32269)

A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some uninitialized portions of the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_223", rls:"EULEROSVIRT-3.0.6.6"))) {
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
