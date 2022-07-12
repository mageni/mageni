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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1521");
  script_version("2020-01-23T12:03:18+0000");
  script_cve_id("CVE-2013-4348", "CVE-2014-5045", "CVE-2014-5206", "CVE-2014-7825", "CVE-2014-8369", "CVE-2014-8989", "CVE-2015-8785", "CVE-2016-2059", "CVE-2016-2185", "CVE-2016-2188", "CVE-2016-3713", "CVE-2016-7039", "CVE-2017-13695", "CVE-2017-15649", "CVE-2017-15951", "CVE-2017-17805", "CVE-2017-6874", "CVE-2017-7895", "CVE-2018-13093", "CVE-2018-7492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:03:18 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:03:18 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1521)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1521");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1521 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The NFSv2 and NFSv3 server implementations in the Linux kernel through 4.10.13 lacked certain checks for the end of a buffer. A remote attacker could trigger a pointer-arithmetic error or possibly cause other unspecified impacts using crafted requests related to fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c.(CVE-2017-7895

A flaw was found in the Linux kernel's ACPI subsystem where a function does not flush the operand cache and causes a kernel stack dump. This allows local users to obtain sensitive information from kernel memory and bypass the KASLR protection mechanism when using a specially crafted ACPI table.(CVE-2017-13695

It was found that fanout_add() in 'net/packet/af_packet.c' in the Linux kernel, before version 4.13.6, allows local users to gain privileges via crafted system calls that trigger mishandling of packet_fanout data structures, because of a race condition (involving fanout_add and packet_do_bind) that leads to a use-after-free bug.(CVE-2017-15649

Race condition in kernel/ucount.c in the Linux kernel through 4.10.2 allows local users to cause a denial of service (use-after-free and system crash) or possibly have unspecified other impact via crafted system calls that leverage certain decrement behavior that causes incorrect interaction between put_ucounts and get_ucounts.(CVE-2017-6874

An out-of-bounds memory access flaw, CVE-2014-7825, was found in the syscall tracing functionality of the Linux kernel's perf subsystem. A local, unprivileged user could use this flaw to crash the system. Additionally, an out-of-bounds memory access flaw, CVE-2014-7826, was found in the syscall tracing functionality of the Linux kernel's ftrace subsystem. On a system with ftrace syscall tracing enabled, a local, unprivileged user could use this flaw to crash the system, or escalate their privileges.(CVE-2014-7825

The Salsa20 encryption algorithm in the Linux kernel, before 4.14.8, does not correctly handle zero-length inputs. This allows a local attacker the ability to use the AF_ALG-based skcipher interface to cause a denial of service (uninitialized-memory free and kernel crash) or have an unspecified other impact by executing a crafted sequence of system calls that use the blkcipher_walk API. Both the generic implementation (crypto/salsa20_generic.c) and x86 implementation (arch/x86/crypto/salsa20_glue.c) of Salsa20 are vulnerable.(CVE-2017-17805

The msm_ipc_router_bind_control_port function in net/ipc_router/ipc_router_core.c in the IPC router kernel module for the Linux kernel 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM device ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.1.0.");

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

if(release == "EULEROSVIRTARM64-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
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