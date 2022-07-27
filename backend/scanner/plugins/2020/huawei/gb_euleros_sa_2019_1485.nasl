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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1485");
  script_version("2020-01-23T15:42:05+0000");
  script_cve_id("CVE-2014-9644", "CVE-2014-9710", "CVE-2014-9715", "CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2014-9892", "CVE-2014-9895", "CVE-2014-9900", "CVE-2014-9904", "CVE-2014-9914", "CVE-2014-9922", "CVE-2014-9940", "CVE-2015-0239", "CVE-2015-0274", "CVE-2015-0275", "CVE-2015-1333", "CVE-2015-1420", "CVE-2015-1421", "CVE-2015-1465", "CVE-2015-1573", "CVE-2015-1593");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 15:42:05 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:53:38 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1485)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1485");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1485 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the Linux kernel's Crypto subsystem handled automatic loading of kernel modules. A local user could use this flaw to load any installed kernel module, and thus increase the attack surface of the running kernel.(CVE-2014-9644)

The Btrfs implementation in the Linux kernel before 3.19 does not ensure that the visible xattr state is consistent with a requested replacement, which allows local users to bypass intended ACL settings and gain privileges via standard filesystem operations (1) during an xattr-replacement time window, related to a race condition, or (2) after an xattr-replacement attempt that fails because the data does not fit.(CVE-2014-9710)

An integer overflow flaw was found in the way the Linux kernel's netfilter connection tracking implementation loaded extensions. An attacker on a local network could potentially send a sequence of specially crafted packets that would initiate the loading of a large number of extensions, causing the targeted system in that network to crash.(CVE-2014-9715)

A symlink size validation was missing in Linux kernels built with UDF file system (CONFIG_UDF_FS) support, allowing the corruption of kernel memory. An attacker able to mount a corrupted/malicious UDF file system image could cause the kernel to crash.(CVE-2014-9728)

A symlink size validation was missing in Linux kernels built with UDF file system (CONFIG_UDF_FS) support, allowing the corruption of kernel memory. An attacker able to mount a corrupted/malicious UDF file system image could cause the kernel to crash.(CVE-2014-9729)

A symlink size validation was missing in Linux kernels built with UDF file system (CONFIG_UDF_FS) support, allowing the corruption of kernel memory. An attacker able to mount a corrupted/malicious UDF file system image could cause the kernel to crash.(CVE-2014-9730)

A path length checking flaw was found in Linux kernels built with UDF file system (CONFIG_UDF_FS) support. An attacker able to mount a corrupted/malicious UDF file system image could use this flaw to leak kernel memory to user-space.(CVE-2014-9731)

The snd_compr_tstamp function in sound/core/compress_offload.c in the Linux kernel through 4.7, as used in Android before 2016-08-05 on Nexus 5 and 7 (2013) devices, does not properly initialize a timestamp data structure, which allows attackers to obtain sensitive information via a crafted application, aka Android internal bug 28770164 and Qualcomm internal bug CR568717.(CVE-2014-9892)

drivers/media/media-device.c in the Linux kernel before 3.11, as used in Android before 2016-08-05 on Nexus 5 and 7 (2013) devices, ...

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