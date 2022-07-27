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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1474");
  script_version("2020-01-23T11:49:48+0000");
  script_cve_id("CVE-2013-2898", "CVE-2013-4514", "CVE-2014-1690", "CVE-2014-4656", "CVE-2014-8160", "CVE-2014-8559", "CVE-2014-9729", "CVE-2015-3212", "CVE-2015-7799", "CVE-2015-7872", "CVE-2016-10200", "CVE-2016-4580", "CVE-2016-7910", "CVE-2017-11600", "CVE-2017-16532", "CVE-2017-5972", "CVE-2018-1066", "CVE-2018-11506", "CVE-2018-14615", "CVE-2018-8781");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:49:48 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:49:48 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1474)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1474");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1474 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The x25_negotiate_facilities function in net/x25/x25_facilities.c in the Linux kernel before 4.5.5 does not properly initialize a certain data structure, which allows attackers to obtain sensitive information from kernel stack memory via an X.25 Call Request.(CVE-2016-4580

A flaw was found in the Linux kernel's implementation of seq_file where a local attacker could manipulate memory in the put() function pointer. This could lead to memory corruption and possible privileged escalation.(CVE-2016-7910

A flaw was found in the way the Linux kernel's netfilter subsystem handled generic protocol tracking. As demonstrated in the Stream Control Transmission Protocol (SCTP) case, a remote attacker could use this flaw to bypass intended iptables rule restrictions when the associated connection tracking module was not loaded on the system.(CVE-2014-8160

The get_endpoints function in drivers/usb/misc/usbtest.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16532

An integer overflow flaw was found in the way the Linux kernel's Advanced Linux Sound Architecture (ALSA) implementation handled user controls. A local, privileged user could use this flaw to crash the system.(CVE-2014-4656

The sr_do_ioctl function in drivers/scsi/sr_ioctl.c in the Linux kernel through 4.16.12 allows local users to cause a denial of service (stack-based buffer overflow) or possibly have unspecified other impact because sense buffers have different sizes at the CDROM layer and the SCSI layer.(CVE-2018-11506

A race condition flaw was found in the way the Linux kernel's SCTP implementation handled Address Configuration lists when performing Address Configuration Change (ASCONF). A local attacker could use this flaw to crash the system via a race condition triggered by setting certain ASCONF options on a socket.(CVE-2015-3212

A symlink size validation was missing in Linux kernels built with UDF file system (CONFIG_UDF_FS) support, allowing the corruption of kernel memory. An attacker able to mount a corrupted/malicious UDF file system image could cause the kernel to crash.(CVE-2014-9729

The Linux kernel before version 4.11 is vulnerable to a NULL pointer dereference in fs/cifs/cifsencrypt.c:setup_ntlmv2_rsp() that allows an attacker controlling a CIFS server to kernel panic a client that has this server mounted, because an empty TargetInfo field in an NTLMSSP setup negotiation response is mishandled during session recovery.(CVE-2018-1066

driv ...

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