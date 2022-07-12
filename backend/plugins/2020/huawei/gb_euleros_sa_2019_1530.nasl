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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1530");
  script_version("2020-01-23T12:06:13+0000");
  script_cve_id("CVE-2013-6380", "CVE-2014-4157", "CVE-2014-4654", "CVE-2014-9585", "CVE-2015-2041", "CVE-2015-7566", "CVE-2015-8956", "CVE-2016-5696", "CVE-2016-9588", "CVE-2017-14051", "CVE-2017-14106", "CVE-2017-15299", "CVE-2017-15868", "CVE-2017-16533", "CVE-2017-7616", "CVE-2017-9984", "CVE-2018-10880", "CVE-2018-13053", "CVE-2018-14611", "CVE-2018-5750");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:06:13 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:06:13 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1530)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1530");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1530 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The acpi_smbus_hc_add function in drivers/acpi/sbshc.c in the Linux kernel through 4.14.15 allows local users to obtain sensitive address information by reading dmesg data from an SBS HC printk call.(CVE-2018-5750

An issue was discovered in the btrfs filesystem code in the Linux kernel. A use-after-free is possible in try_merge_free_space() when mounting a crafted btrfs image due to a lack of chunk type flag checks in btrfs_check_chunk_valid() in the fs/btrfs/volumes.c function. This could lead to a denial of service or other unspecified impact.(CVE-2018-14611

A flaw was found in the way the Linux kernel visor driver handles certain invalid USB device descriptors. The driver assumes that the device always has at least one bulk OUT endpoint. By using a specially crafted USB device (without a bulk OUT endpoint), an unprivileged user with physical access could trigger a kernel NULL-pointer dereference and cause a system panic (denial of service).(CVE-2015-7566

It was found that the RFC 5961 challenge ACK rate limiting as implemented in the Linux kernel's networking subsystem allowed an off-path attacker to leak certain information about a given connection by creating congestion on the global challenge ACK rate limit counter and then measuring the changes by probing packets. An off-path attacker could use this flaw to either terminate TCP connection and/or inject payload into non-secured TCP connection between two endpoints on the network.(CVE-2016-5696

It was found that the Bluebooth Network Encapsulation Protocol (BNEP) implementation did not validate the type of second socket passed to the BNEPCONNADD ioctl(), which could lead to memory corruption. A local user with the CAP_NET_ADMIN capability can use this for denial of service (crash or data corruption) or possibly for privilege escalation. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although we feel it is unlikely.(CVE-2017-15868

A vulnerability was found in the key management subsystem of the Linux kernel. An update on an uninstantiated key could cause a kernel panic, leading to denial of service (DoS).(CVE-2017-15299

The rfcomm_sock_bind function in net/bluetooth/rfcomm/sock.c in the Linux kernel before 4.2 allows local users to obtain sensitive information or cause a denial of service (NULL pointer dereference) via vectors involving a bind system call on a Bluetooth RFCOMM socket.(CVE-2015-8956

arch/mips/include/asm/thread_info.h in the Linux kernel before 3.14.8 on the MIPS platform does not configure _TIF_SECCOMP checks on the fast system-call path, which allows loca ...

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