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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1476");
  script_version("2020-01-23T11:50:31+0000");
  script_cve_id("CVE-2013-2895", "CVE-2013-4516", "CVE-2014-7283", "CVE-2015-2877", "CVE-2015-3636", "CVE-2015-4003", "CVE-2015-4004", "CVE-2015-8952", "CVE-2015-8964", "CVE-2016-2061", "CVE-2016-3137", "CVE-2017-17806", "CVE-2017-18193", "CVE-2017-18255", "CVE-2017-5550", "CVE-2017-8824", "CVE-2018-1092", "CVE-2018-12633", "CVE-2018-14609", "CVE-2018-8822");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:50:31 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:50:31 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1476)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1476");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1476 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free vulnerability was found in DCCP socket code affecting the Linux kernel since 2.6.16. This vulnerability could allow an attacker to their escalate privileges.(CVE-2017-8824

The OZWPAN driver in the Linux kernel through 4.0.5 relies on an untrusted length field during packet parsing, which allows remote attackers to obtain sensitive information from kernel memory or cause a denial of service (out-of-bounds read and system crash) via a crafted packet.(CVE-2015-4004

Integer signedness error in the MSM V4L2 video driver for the Linux kernel 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, allows attackers to gain privileges or cause a denial of service (array overflow and memory corruption) via a crafted application that triggers an msm_isp_axi_create_stream call.(CVE-2016-2061

A denial of service flaw was found in the way the Linux kernel's XFS file system implementation ordered directory hashes under certain conditions. A local attacker could use this flaw to corrupt the file system by creating directories with colliding hash values, potentially resulting in a system crash.(CVE-2014-7283

It was found that the Linux kernel's ping socket implementation did not properly handle socket unhashing during spurious disconnects, which could lead to a use-after-free flaw. On x86-64 architecture systems, a local user able to create ping sockets could use this flaw to crash the system. On non-x86-64 architecture systems, a local user able to create ping sockets could use this flaw to escalate their privileges on the system.(CVE-2015-3636

Incorrect buffer length handling was found in the ncp_read_kernel function in fs/ncpfs/ncplib_kernel.c in the Linux kernel, which could be exploited by malicious NCPFS servers to crash the kernel or possibly execute an arbitrary code.(CVE-2018-8822

** DISPUTED ** Kernel Samepage Merging (KSM) in the Linux kernel 2.6.32 through 4.x does not prevent use of a write-timing side channel, which allows guest OS users to defeat the ASLR protection mechanism on other guest OS instances via a Cross-VM ASL INtrospection (CAIN) attack. NOTE: the vendor states 'Basically if you care about this attack vector, disable deduplication.' Share-until-written approaches for memory conservation among mutually untrusting tenants are inherently detectable for information disclosure, and can be classified as potentially misunderstood behaviors rather than vulnerabilities.(CVE-2015-2877

The tty_set_termios_ldisc() function in 'drivers/tty/tty_ldisc.c' in the Linux kernel before 4.5 allows lo ...

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