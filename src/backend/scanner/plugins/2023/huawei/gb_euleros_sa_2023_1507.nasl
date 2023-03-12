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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1507");
  script_cve_id("CVE-2020-27066", "CVE-2021-0512", "CVE-2021-39634", "CVE-2022-0812", "CVE-2022-1184", "CVE-2022-1679", "CVE-2022-2503", "CVE-2022-2663", "CVE-2022-2964", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-3524", "CVE-2022-3542", "CVE-2022-3545", "CVE-2022-3565", "CVE-2022-3566", "CVE-2022-3567", "CVE-2022-3586", "CVE-2022-3594", "CVE-2022-3628", "CVE-2022-3629", "CVE-2022-39188", "CVE-2022-40768", "CVE-2022-4095", "CVE-2022-41850", "CVE-2022-42703", "CVE-2022-43750");
  script_tag(name:"creation_date", value:"2023-03-09 04:15:24 +0000 (Thu, 09 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 18:18:00 +0000 (Mon, 06 Feb 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-1507)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1507");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1507");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-1507 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-component. This flaw allows a local attacker with a user privilege to cause a denial of service.(CVE-2022-1184)

A use-after-free flaw was found in Linux kernel before 5.19.2. This issue occurs in cmd_hdl_filter in drivers/staging/rtl8712/rtl8712_cmd.c, allowing an attacker to launch a local denial of service attack and gain escalation of privileges.(CVE-2022-4095)

A buffer overflow flaw was found in the Linux kernel Broadcom Full MAC Wi-Fi driver. This issue occurs when a user connects to a malicious USB device. This can allow a local user to crash the system or escalate their privileges(CVE-2022-3628)

A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects the function vsock_connect of the file net/vmw_vsock/af_vsock.c of the component IPsec. The manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211930 is the identifier assigned to this vulnerability.(CVE-2022-3629)

A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects the function inet6_stream_ops/inet6_dgram_ops of the component IPv6 Handler. The manipulation leads to race condition. It is recommended to apply a patch to fix this issue. VDB-211090 is the identifier assigned to this vulnerability.(CVE-2022-3567)

drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-space client to corrupt the monitor's internal memory.(CVE-2022-43750)

A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier VDB-211045 was assigned to this vulnerability.(CVE-2022-3545)

A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed) into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of service.(CVE-2022-3586)

A vulnerability, which was classified as problematic, was found in Linux Kernel. This affects the function tcp_getsockopt/tcp_setsockopt of the component TCP Handler. The manipulation leads to race condition. It is recommended to apply a patch to fix this issue. The identifier VDB-211089 was assigned to this vulnerability.(CVE-2022-3566)

A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The manipulation leads ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.5.h733.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.5.h733.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.5.h733.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.5.h733.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.5.h733.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.5.h733.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.5.h733.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
