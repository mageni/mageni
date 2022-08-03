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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2194");
  script_cve_id("CVE-2021-3667", "CVE-2021-3750", "CVE-2022-26354");
  script_tag(name:"creation_date", value:"2022-08-01 04:38:15 +0000 (Mon, 01 Aug 2022)");
  script_version("2022-08-02T10:11:24+0000");
  script_tag(name:"last_modification", value:"2022-08-02 10:11:24 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-16 18:14:00 +0000 (Mon, 16 May 2022)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2022-2194)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2194");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2194");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2022-2194 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A DMA reentrancy issue was found in the USB EHCI controller emulation of QEMU. EHCI does not verify if the Buffer Pointer overlaps with its MMIO region when it transfers the USB packets. Crafted content may be written to the controller's registers and trigger undesirable actions (such as reset) while the device is still transferring packets. This can ultimately lead to a use-after-free issue. A malicious guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service condition, or potentially execute arbitrary code within the context of the QEMU process on the host. This flaw affects QEMU versions before 7.0.0.(CVE-2021-3750)

An improper locking issue was found in the virStoragePoolLookupByTargetPath API of libvirt. It occurs in the storagePoolLookupByTargetPath function where a locked virStoragePoolObj object is not properly released on ACL permission failure. Clients connecting to the read-write socket with limited ACL permissions could use this flaw to acquire the lock and prevent other users from accessing storage pool/volume APIs, resulting in a denial of service condition. The highest threat from this vulnerability is to system availability.(CVE-2021-3667)

A flaw was found in the vhost-vsock device of QEMU. In case of error, an invalid element was not detached from the virtqueue before freeing its memory, leading to memory leakage and other unexpected results. Affected QEMU versions <= 6.2.0.(CVE-2022-26354)");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~4.1.0~2.9.1.2.369", rls:"EULEROSVIRT-2.9.1"))) {
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
