# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1265");
  script_version("2020-01-23T11:19:31+0000");
  script_cve_id("CVE-2018-1087", "CVE-2018-3639");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-23 11:19:31 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:19:31 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kvm (EulerOS-SA-2018-1265)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.1");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1265");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kvm' package(s) announced via the EulerOS-SA-2018-1265 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An industry-wide issue was found in the way many modern microprocessor designs have implemented speculative execution of Load  Store instructions (a commonly used performance optimization). It relies on the presence of a precisely-defined instruction sequence in the privileged code as well as the fact that memory read from address to which a recent memory write has occurred may see an older value and subsequently cause an update into the microprocessor's data cache even for speculatively executed instructions that never actually commit (retire). As a result, an unprivileged attacker could use this flaw to read privileged memory by conducting targeted cache side-channel attacks.(CVE-2018-3639)

On x86, MOV SS and POP SS behave strangely if they encounter a data breakpoint. If this occurs in a KVM guest, KVM incorrectly thinks that a #DB instruction was caused by the undocumented ICEBP instruction. This results in #DB being delivered to the guest kernel with an incorrect RIP on the stack. On most guest kernels, this will allow a guest user to DoS the guest kernel or even to escalate privilege to that of the guest kernel. (CVE-2018-1087)");

  script_tag(name:"affected", value:"'kvm' package(s) on Huawei EulerOS Virtualization 2.5.1.");

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

if(release == "EULEROSVIRT-2.5.1") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~4.4.11~519", rls:"EULEROSVIRT-2.5.1"))) {
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