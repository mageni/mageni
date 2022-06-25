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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1418");
  script_cve_id("CVE-2019-12067", "CVE-2020-15859", "CVE-2020-25084", "CVE-2020-25742", "CVE-2020-25743", "CVE-2020-35504", "CVE-2020-35505", "CVE-2021-20196", "CVE-2021-20203", "CVE-2021-20221", "CVE-2021-20255", "CVE-2021-3544", "CVE-2021-3545", "CVE-2021-3546", "CVE-2021-3682", "CVE-2021-3748");
  script_tag(name:"creation_date", value:"2022-04-13 11:57:51 +0000 (Wed, 13 Apr 2022)");
  script_version("2022-04-13T11:57:51+0000");
  script_tag(name:"last_modification", value:"2022-04-14 10:40:31 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-29 18:58:00 +0000 (Tue, 29 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2022-1418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1418");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1418");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2022-1418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"QEMU 5.0.0 has a use-after-free in hw/usb/hcd-xhci.c because the usb_packet_map return value is not checked. (CVE-2020-25084)

A flaw was found in the USB redirector device emulation of QEMU in versions prior to 6.1.0-rc2. It occurs when dropping packets during a bulk transfer from a SPICE client due to the packet queue being full. A malicious SPICE client could use this flaw to make QEMU call free() with faked heap chunk metadata, resulting in a crash of QEMU or potential code execution with the privileges of the QEMU process on the host. (CVE-2021-3682)

QEMU 4.2.0 has a use-after-free in hw/net/e1000e_core.c because a guest OS user can trigger an e1000e packet with the data's address set to the e1000e's MMIO address.(CVE-2020-15859)

A NULL pointer dereference flaw was found in the am53c974 SCSI host bus adapter emulation of QEMU in versions before 6.0.0. This issue occurs while handling the 'Information Transfer' command. This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2020-35505)

Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions up to and including 6.0. They exist in contrib/vhost-user-gpu/vhost-user-gpu.c and contrib/vhost-user-gpu/virgl.c due to improper release of memory (i.e., free) after effective lifetime.(CVE-2021-3544)

A flaw was found in vhost-user-gpu of QEMU in versions up to and including 6.0. An out-of-bounds write vulnerability can allow a malicious guest to crash the QEMU process on the host resulting in a denial of service or potentially execute arbitrary code on the host with the privileges of the QEMU process. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2021-3546)

An information disclosure vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions up to and including 6.0. The flaw exists in virgl_cmd_get_capset_info() in contrib/vhost-user-gpu/virgl.c and could occur due to the read of uninitialized memory. A malicious guest could exploit this issue to leak memory from the host.(CVE-2021-3545)

An out-of-bounds heap buffer access issue was found in the ARM Generic Interrupt Controller emulator of QEMU up to and including qemu 4.2.0on aarch64 platform. The issue occurs because while writing an interrupt ID to the controller memory area, it is not masked to be 4 bits wide. It may lead to the said issue while updating controller state fields and their subsequent processing. A privileged guest user may use this flaw to crash the QEMU process on the host resulting in DoS scenario.(CVE-2021-20221)

A NULL pointer dereference flaw was found in the SCSI emulation support of QEMU in versions before 6.0.0. This flaw allows a privileged guest user to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~4.1.0~2.10.0.3.427", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~4.1.0~2.10.0.3.427", rls:"EULEROSVIRT-2.10.0"))) {
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
