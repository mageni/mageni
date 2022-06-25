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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1014");
  script_cve_id("CVE-2019-12067", "CVE-2020-13754", "CVE-2020-25085", "CVE-2020-25742", "CVE-2020-25743", "CVE-2020-27617", "CVE-2020-27821", "CVE-2020-29129", "CVE-2020-29443", "CVE-2020-35504", "CVE-2020-35505", "CVE-2021-20181", "CVE-2021-20203", "CVE-2021-20221", "CVE-2021-3392", "CVE-2021-3416", "CVE-2021-3527", "CVE-2021-3544", "CVE-2021-3545", "CVE-2021-3546", "CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3595", "CVE-2021-3682", "CVE-2021-3713", "CVE-2021-3748");
  script_tag(name:"creation_date", value:"2022-01-28 03:17:04 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T03:17:04+0000");
  script_tag(name:"last_modification", value:"2022-01-28 11:09:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-17 17:29:00 +0000 (Tue, 17 Aug 2021)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2022-1014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1014");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1014");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2022-1014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the udp6_input() function and could occur while processing a udp packet that is smaller than the size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw affects libslirp versions prior to 4.6.0.(CVE-2021-3593)

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the tftp_input() function and could occur while processing a udp packet that is smaller than the size of the 'tftp_t' structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw affects libslirp versions prior to 4.6.0.(CVE-2021-3595)

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the bootp_input() function and could occur while processing a udp packet that is smaller than the size of the 'bootp_t' structure. A malicious guest could use this flaw to leak 10 bytes of uninitialized heap memory from the host. The highest threat from this vulnerability is to data confidentiality. This flaw affects libslirp versions prior to 4.6.0.(CVE-2021-3592)

An out-of-bounds write flaw was found in the UAS (USB Attached SCSI) device emulation of QEMU in versions prior to 6.2.0-rc0. The device uses the guest supplied stream number unchecked, which can lead to out-of-bounds access to the UASDevice->data3 and UASDevice->status3 fields. A malicious guest user could use this flaw to crash QEMU or potentially achieve code execution with the privileges of the QEMU process on the host.(CVE-2021-3713)

A use-after-free vulnerability was found in the virtio-net device of QEMU. It could occur when the descriptor's address belongs to the non direct access region, due to num_buffers being set after the virtqueue elem has been unmapped. A malicious guest could use this flaw to crash QEMU, resulting in(CVE-2021-3748)

QEMU 5.0.0 has a heap-based Buffer Overflow in flatview_read_continue in exec.c because hw/sd/sdhci.c mishandles a write operation in the SDHC_BLKSIZE case.(CVE-2020-25085)

A potential stack overflow via infinite loop issue was found in various NIC emulators of QEMU in versions up to and including 5.2.0. The issue occurs in loopback mode of a NIC wherein reentrant DMA checks get bypassed. A guest user/process may use this flaw to consume CPU cycles or crash the QEMU process on the host resulting in DoS scenario.(CVE-2021-3416)

Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions up to and including 6.0. They exist in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~4.1.0~16.h10.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
