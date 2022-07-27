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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1479");
  script_version("2020-01-23T11:51:32+0000");
  script_cve_id("CVE-2014-0196", "CVE-2014-0206", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446", "CVE-2014-1690", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-1739", "CVE-2014-1874", "CVE-2014-2038", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2568", "CVE-2014-2672", "CVE-2014-2673", "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3122", "CVE-2014-3144", "CVE-2014-3145");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:51:32 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:51:32 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1479)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1479");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1479 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel through 3.14.3 does not properly manage tty driver access in the 'LECHO  !OPOST' case, which allows local users to cause a denial of service (memory corruption and system crash) or gain privileges by triggering a race condition involving read and write operations with long strings.(CVE-2014-0196)

Array index error in the aio_read_events_ring function in fs/aio.c in the Linux kernel through 3.15.1 allows local users to obtain sensitive information from kernel memory via a large head value.(CVE-2014-0206)

The fst_get_iface function in drivers/net/wan/farsync.c in the Linux kernel before 3.11.7 does not properly initialize a certain data structure, which allows local users to obtain sensitive information from kernel memory by leveraging the CAP_NET_ADMIN capability for an SIOCWANDEV ioctl call.(CVE-2014-1444)

The wanxl_ioctl function in drivers/net/wan/wanxl.c in the Linux kernel before 3.11.7 does not properly initialize a certain data structure, which allows local users to obtain sensitive information from kernel memory via an ioctl call.(CVE-2014-1445)

The yam_ioctl function in drivers/net/hamradio/yam.c in the Linux kernel before 3.12.8 does not initialize a certain structure member, which allows local users to obtain sensitive information from kernel memory by leveraging the CAP_NET_ADMIN capability for an SIOCYAMGCFG ioctl call.(CVE-2014-1446)

The help function in net/netfilter/nf_nat_irc.c in the Linux kernel before 3.12.8 allows remote attackers to obtain sensitive information from kernel memory by establishing an IRC DCC session in which incorrect packet data is transmitted during use of the NAT mangle feature.(CVE-2014-1690)

A flaw was found in the way the Linux kernel's floppy driver handled user space provided data in certain error code paths while processing FDRAWCMD IOCTL commands. A local user with write access to /dev/fdX could use this flaw to free (using the kfree() function) arbitrary kernel memory. (CVE-2014-1737, Important)
It was found that the Linux kernel's floppy driver leaked internal kernel memory addresses to user space during the processing of the FDRAWCMD IOCTL command. A local user with write access to /dev/fdX could use this flaw to obtain information about the kernel heap arrangement. (CVE-2014-1738, Low)
Note: A local user with write access to /dev/fdX could use these two flaws (CVE-2014-1737 in combination with CVE-2014-1738) to escalate their privileges on the system.(CVE-2014-1737)

A flaw was found in the way the Linux kernel's floppy driver handled user space provided ...

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