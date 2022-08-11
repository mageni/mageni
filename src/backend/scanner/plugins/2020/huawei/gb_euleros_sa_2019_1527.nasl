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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1527");
  script_version("2020-01-23T12:05:12+0000");
  script_cve_id("CVE-2013-4470", "CVE-2014-0131", "CVE-2014-1874", "CVE-2014-3181", "CVE-2014-8134", "CVE-2014-9410", "CVE-2014-9428", "CVE-2014-9940", "CVE-2015-5327", "CVE-2015-5364", "CVE-2015-8787", "CVE-2015-8812", "CVE-2016-0728", "CVE-2016-10318", "CVE-2016-2069", "CVE-2016-4794", "CVE-2017-12192", "CVE-2017-18203", "CVE-2017-18344", "CVE-2017-6074");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:05:12 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:05:12 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1527)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1527");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1527 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Linux kernel, before version 4.14.3, is vulnerable to a denial of service in drivers/md/dm.c:dm_get_from_kobject() which can be caused by local users leveraging a race condition with __dm_destroy() during creation and removal of DM devices. Only privileged local users (with CAP_SYS_ADMIN capability) can directly perform the ioctl operations for dm device creation and removal and this would typically be outside the direct control of the unprivileged attacker.(CVE-2017-18203

The batadv_frag_merge_packets function in net/batman-adv/fragmentation.c in the B.A.T.M.A.N. implementation in the Linux kernel through 3.18.1 uses an incorrect length field during a calculation of an amount of memory, which allows remote attackers to cause a denial of service (mesh-node system crash) via fragmented packets.(CVE-2014-9428

The regulator_ena_gpio_free function in drivers/regulator/core.c in the Linux kernel allows local users to gain privileges or cause a denial of service (use-after-free) via a crafted application.(CVE-2014-9940

The Linux kernel before 3.12, when UDP Fragmentation Offload (UFO) is enabled, does not properly initialize certain data structures, which allows local users to cause a denial of service (memory corruption and system crash) or possibly gain privileges via a crafted application that uses the UDP_CORK option in a setsockopt system call and sends both short and long packets, related to the ip_ufo_append_data function in net/ipv4/ip_output.c and the ip6_ufo_append_data function in net/ipv6/ip6_output.c.(CVE-2013-4470

A use-after-free flaw was found in the way the Linux kernel's Datagram Congestion Control Protocol (DCCP) implementation freed SKB (socket buffer) resources for a DCCP_PKT_REQUEST packet when the IPV6_RECVPKTINFO option is set on the socket. A local, unprivileged user could use this flaw to alter the kernel memory, allowing them to escalate their privileges on the system.(CVE-2017-6074

A NULL-pointer dereference vulnerability was found in the Linux kernel's TCP stack, in net/netfilter/nf_nat_redirect.c in the nf_nat_redirect_ipv4() function. A remote, unauthenticated user could exploit this flaw to create a system crash (denial of service).(CVE-2015-8787

A use-after-free flaw was found in the CXGB3 kernel driver when the network was considered to be congested. The kernel incorrectly misinterpreted the congestion as an error condition and incorrectly freed or cleaned up the socket buffer (skb). When the device then sent the skb's queued data, these structures were referenced. A local attacker could use this flaw to panic the system (denia ...

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