# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6283.1");
  script_cve_id("CVE-2023-2002", "CVE-2023-2269", "CVE-2023-3141", "CVE-2023-32248", "CVE-2023-32254", "CVE-2023-3268", "CVE-2023-3312", "CVE-2023-3317", "CVE-2023-35823", "CVE-2023-35824", "CVE-2023-35826", "CVE-2023-35828", "CVE-2023-35829");
  script_tag(name:"creation_date", value:"2023-08-14 04:08:46 +0000 (Mon, 14 Aug 2023)");
  script_version("2023-08-14T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-08-14 05:05:34 +0000 (Mon, 14 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-17 17:55:00 +0000 (Mon, 17 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6283-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU23\.04");

  script_xref(name:"Advisory-ID", value:"USN-6283-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6283-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-ibm, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) announced via the USN-6283-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ruihan Li discovered that the bluetooth subsystem in the Linux kernel did
not properly perform permissions checks when handling HCI sockets. A
physically proximate attacker could use this to cause a denial of service
(bluetooth communication). (CVE-2023-2002)

Zheng Zhang discovered that the device-mapper implementation in the Linux
kernel did not properly handle locking during table_clear() operations. A
local attacker could use this to cause a denial of service (kernel
deadlock). (CVE-2023-2269)

It was discovered that the Ricoh R5C592 MemoryStick card reader driver in
the Linux kernel contained a race condition during module unload, leading
to a use-after-free vulnerability. A local attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-3141)

Quentin Minster discovered that the KSMBD implementation in the Linux
kernel did not properly validate pointers in some situations, leading to a
null pointer dereference vulnerability. A remote attacker could use this to
cause a denial of service (system crash). (CVE-2023-32248)

Quentin Minster discovered that a race condition existed in the KSMBD
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A remote attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2023-32254)

It was discovered that the kernel->user space relay implementation in the
Linux kernel did not properly perform certain buffer calculations, leading
to an out-of-bounds read vulnerability. A local attacker could use this to
cause a denial of service (system crash) or expose sensitive information
(kernel memory). (CVE-2023-3268)

It was discovered that the QCOM CPUFreq HW driver in the Linux kernel on
ARM processors did not properly handle device unbind. A local attacker
could use this to cause a denial of service (system crash). (CVE-2023-3312)

It was discovered that the MediaTek MT7921E (PCIe) WiFi driver in the Linux
kernel contained a use-after-free vulnerability when querying the firmware
features of the device. A local attacker could use this to cause a denial
of service (system crash). (CVE-2023-3317)

It was discovered that the video4linux driver for Philips based TV cards in
the Linux kernel contained a race condition during device removal, leading
to a use-after-free vulnerability. A physically proximate attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-35823)

It was discovered that the SDMC DM1105 PCI device driver in the Linux
kernel contained a race condition during device removal, leading to a use-
after-free vulnerability. A physically proximate attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-35824)

It was discovered that the Allwinner Cedar video engine driver in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-ibm, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) on Ubuntu 23.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1007-ibm", ver:"6.2.0-1007.7", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1009-aws", ver:"6.2.0-1009.9", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1009-azure", ver:"6.2.0-1009.9", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1009-oracle", ver:"6.2.0-1009.9", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1010-kvm", ver:"6.2.0-1010.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1010-lowlatency", ver:"6.2.0-1010.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1010-lowlatency-64k", ver:"6.2.0-1010.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1010-raspi", ver:"6.2.0-1010.12", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1011-gcp", ver:"6.2.0-1011.11", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-27-generic", ver:"6.2.0-27.28", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-27-generic-64k", ver:"6.2.0-27.28", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-27-generic-lpae", ver:"6.2.0-27.28", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.2.0.1009.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.2.0.1009.9", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.2.0.1011.11", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.2.0.27.27", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.2.0.27.27", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.2.0.27.27", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"6.2.0.1007.7", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.2.0.1010.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.2.0.1010.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.2.0.1010.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.2.0.1009.9", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.2.0.1010.13", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"6.2.0.1010.13", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.2.0.27.27", rls:"UBUNTU23.04"))) {
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
