# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883177");
  script_version("2020-06-05T06:49:56+0000");
  script_cve_id("CVE-2019-11135", "CVE-2019-14378");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-06-05 10:05:11 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-02-06 04:00:37 +0000 (Thu, 06 Feb 2020)");
  script_name("CentOS: Security Advisory for qemu-img (CESA-2020:0366)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-February/035623.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-img'
  package(s) announced via the CESA-2020:0366 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kernel-based Virtual Machine (KVM) is a full virtualization solution for
Linux on a variety of architectures. The qemu-kvm packages provide the
user-space component for running virtual machines that use KVM.

Security Fix(es):

  * hw: TSX Transaction Asynchronous Abort (TAA) (CVE-2019-11135)

  * QEMU: slirp: heap buffer overflow during packet reassembly
(CVE-2019-14378)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * [Intel 7.8 Bug] [KVM][CLX] CPUID_7_0_EDX_ARCH_CAPABILITIES is not enabled
in VM qemu-kvm (BZ#1730606)

Enhancement(s):

  * [Intel 7.8 FEAT] MDS_NO exposure to guest - qemu-kvm (BZ#1755333)


After installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update to
take effect.

1734745 - CVE-2019-14378 QEMU: slirp: heap buffer overflow during packet reassembly
1753062 - CVE-2019-11135 hw: TSX Transaction Asynchronous Abort (TAA)

6. Package List:

Red Hat Enterprise Linux Client (v. 7):

Source:
qemu-kvm-1.5.3-167.el7_7.4.src.rpm

x86_64:
qemu-img-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-common-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-debuginfo-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-tools-1.5.3-167.el7_7.4.x86_64.rpm

Red Hat Enterprise Linux ComputeNode Optional (v. 7):

Source:
qemu-kvm-1.5.3-167.el7_7.4.src.rpm

x86_64:
qemu-img-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-common-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-debuginfo-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-tools-1.5.3-167.el7_7.4.x86_64.rpm

Red Hat Enterprise Linux Server (v. 7):

Source:
qemu-kvm-1.5.3-167.el7_7.4.src.rpm

x86_64:
qemu-img-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-common-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-debuginfo-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-tools-1.5.3-167.el7_7.4.x86_64.rpm

Red Hat Enterprise Linux Workstation (v. 7):

Source:
qemu-kvm-1.5.3-167.el7_7.4.src.rpm

x86_64:
qemu-img-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-common-1.5.3-167.el7_7.4.x86_64.rpm
qemu-kvm-debuginfo-1.5.3-167.el7_7.4.x86_64.rp ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'qemu-img' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~167.el7_7.4", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~167.el7_7.4", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~167.el7_7.4", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~167.el7_7.4", rls:"CentOS7"))) {
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
