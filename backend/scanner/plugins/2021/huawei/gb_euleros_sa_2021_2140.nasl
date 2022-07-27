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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2140");
  script_version("2021-07-07T09:11:54+0000");
  script_cve_id("CVE-2019-15239", "CVE-2019-19078", "CVE-2019-9456", "CVE-2020-0305", "CVE-2020-0427", "CVE-2020-0431", "CVE-2020-10773", "CVE-2020-11668", "CVE-2020-12654", "CVE-2020-14331", "CVE-2020-14351", "CVE-2020-14386", "CVE-2020-15436", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-25705", "CVE-2020-28974", "CVE-2020-29370", "CVE-2020-29661");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-07-07 09:11:54 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-07 08:43:14 +0000 (Wed, 07 Jul 2021)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2021-2140)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2140");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2140");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2021-2140 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A memory leak in the ath10k_usb_hif_tx_sg() function in drivers/net/wireless/ath/ath10k/usb.c in the Linux kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering usb_submit_urb() failures, aka CID-b8d17e7d93d2.(CVE-2019-19078)

In the Linux kernel before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink camera USB driver) mishandles invalid descriptors, aka CID-a246b4d54770.(CVE-2020-11668)

An issue was found in Linux kernel before 5.5.4. mwifiex_ret_wmm_get_status() in drivers/net/wireless/marvell/mwifiex/wmm.c allows a remote AP to trigger a heap-based buffer overflow because of an incorrect memcpy, aka CID-3a9b153c5591.(CVE-2020-12654)

A flaw was found in the way the Linux kernel's networking subsystem handled the write queue between TCP disconnection and re-connections. A local attacker could use this flaw to trigger multiple use-after-free conditions potentially escalating their privileges on the system.(CVE-2019-15239)

A use-after-free flaw was found in the way the Linux kernel's filesystem subsystem handled a race condition in the chrdev_open function. This flaw allows a privileged local user to starve the resources, causing a denial of service or potentially escalating their privileges. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.(CVE-2020-0305)

A flaw was found in the Linux pinctrl system. It is possible to trigger an of bounds read due to a use after free. This could lead to local information disclosure with no additional execution privileges needed.(CVE-2020-0427)

A stack information leak flaw was found in s390/s390x in the Linux kernels memory manager functionality, where it incorrectly writes to the /proc/sys/vm/cmm_timeout file. This flaw allows a local user to see the kernel data.(CVE-2020-10773)

A flaw was found in the Linux kernels implementation of the invert video code on VGA consoles when a local attacker attempts to resize the console, calling an ioctl VT_RESIZE, which causes an out-of-bounds write to occur. This flaw allows a local user with access to the VGA console to crash the system, potentially escalating their privileges on the system. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-14331)
A flaw was found in the Linux kernel. A use-after-free memory flaw was found in the perf subsystem allowing a local attacker with permission to monitor perf events to corrupt memory and possibly escalate privileges. The highest threat from this vulnerability i ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_77.x86_64", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_77.x86_64", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_77.x86_64", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_77.x86_64", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_77.x86_64", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_77.x86_64", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_77.x86_64", rls:"EULEROSVIRT-3.0.2.2"))) {
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