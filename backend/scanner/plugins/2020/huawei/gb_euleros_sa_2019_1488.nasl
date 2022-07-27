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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1488");
  script_version("2020-01-23T11:54:37+0000");
  script_cve_id("CVE-2015-5157", "CVE-2015-5257", "CVE-2015-5283", "CVE-2015-5307", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5697", "CVE-2015-5707", "CVE-2015-6252", "CVE-2015-6526", "CVE-2015-6937", "CVE-2015-7312", "CVE-2015-7513", "CVE-2015-7515", "CVE-2015-7550", "CVE-2015-7566", "CVE-2015-7613", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104", "CVE-2015-8215");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:54:37 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:54:37 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1488)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1488");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1488 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the Linux kernel handled IRET faults during the processing of NMIs. An unprivileged, local user could use this flaw to crash the system or, potentially (although highly unlikely), escalate their privileges on the system.(CVE-2015-5157)

A denial of service vulnerability was found in the WhiteHEAT USB Serial Driver (whiteheat_attach function in drivers/usb/serial/whiteheat.c). In the driver, the COMMAND_PORT variable was hard coded and set to 4 (5th element). The driver assumed that the number of ports would always be 5 and used port number 5 as the command port. However, when using a USB device in which the number of ports was set to a number less than 5 (for example, 3), the driver triggered a kernel NULL-pointer dereference. A non-privileged attacker could use this flaw to panic the host.(CVE-2015-5257)

A NULL pointer dereference flaw was found in the SCTP implementation. A local user could use this flaw to cause a denial of service on the system by triggering a kernel panic when creating multiple sockets in parallel while the system did not have the SCTP module loaded.(CVE-2015-5283)

It was found that the x86 ISA (Instruction Set Architecture) is prone to a denial of service attack inside a virtualized environment in the form of an infinite loop in the microcode due to the way (sequential) delivering of benign exceptions such as #AC (alignment check exception) is handled. A privileged user inside a guest could use this flaw to create denial of service conditions on the host kernel.(CVE-2015-5307)

A flaw was found in the way the Linux kernel's networking implementation handled UDP packets with incorrect checksum values. A remote attacker could potentially use this flaw to trigger an infinite loop in the kernel, resulting in a denial of service on the system, or cause a denial of service in applications using the edge triggered epoll functionality.(CVE-2015-5364)

A flaw was found in the way the Linux kernel's networking implementation handled UDP packets with incorrect checksum values. A remote attacker could potentially use this flaw to trigger an infinite loop in the kernel, resulting in a denial of service on the system, or cause a denial of service in applications using the edge triggered epoll functionality.(CVE-2015-5366)

A cross-boundary flaw was discovered in the Linux kernel software raid driver. The driver accessed a disabled bitmap where only the first byte of the buffer was initialized to zero. This meant that the rest of the request (up to 4095 bytes) was left and copied into user space. An attacker could use this flaw to read pr ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
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