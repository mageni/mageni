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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1043");
  script_version("2021-01-08T23:22:45+0000");
  script_cve_id("CVE-2020-14374", "CVE-2020-14375", "CVE-2020-14376", "CVE-2020-14377");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-01-12 11:05:42 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-08 21:54:23 +0000 (Fri, 08 Jan 2021)");
  script_name("Huawei EulerOS: Security Advisory for spdk (EulerOS-SA-2021-1043)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.2\.0");

  script_xref(name:"EulerOS-SA", value:"2021-1043");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1043");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'spdk' package(s) announced via the EulerOS-SA-2021-1043 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in dpdk in versions before 18.11.10 and before 19.11.5. A flawed bounds checking in the copy_data function leads to a buffer overflow allowing an attacker in a virtual machine to write arbitrary data to any address in the vhost_crypto application. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-14374)
A flaw was found in dpdk in versions before 18.11.10 and before 19.11.5. Virtio ring descriptors, and the data they describe are in a region of memory accessible by from both the virtual machine and the host. An attacker in a VM can change the contents of the memory after vhost_crypto has validated it. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-14375)
A flaw was found in dpdk in versions before 18.11.10 and before 19.11.5. A lack of bounds checking when copying iv_data from the VM guest memory into host memory can lead to a large buffer overflow. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-14376)
A flaw was found in dpdk in versions before 18.11.10 and before 19.11.5. A complete lack of validation of attacker-controlled parameters can lead to a buffer over read. The results of the over read are then written back to the guest virtual machine memory. This vulnerability can be used by an attacker in a virtual machine to read significant amounts of host memory. The highest threat from this vulnerability is to data confidentiality and system availability.(CVE-2020-14377)");

  script_tag(name:"affected", value:"'spdk' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"spdk", rpm:"spdk~19.01.1~126", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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