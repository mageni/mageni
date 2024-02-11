# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6624.1");
  script_cve_id("CVE-2023-34324", "CVE-2023-35827", "CVE-2023-46813", "CVE-2023-46862", "CVE-2023-5972", "CVE-2023-6176", "CVE-2023-6531", "CVE-2023-6622", "CVE-2024-0641");
  script_tag(name:"creation_date", value:"2024-02-08 04:08:50 +0000 (Thu, 08 Feb 2024)");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 20:31:31 +0000 (Thu, 30 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6624-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6624-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6624-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-hwe-6.5, linux-laptop, linux-lowlatency, linux-lowlatency-hwe-6.5, linux-oem-6.5, linux-oracle, linux-raspi, linux-starfive' package(s) announced via the USN-6624-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marek Marczykowski-Gorecki discovered that the Xen event channel
infrastructure implementation in the Linux kernel contained a race
condition. An attacker in a guest VM could possibly use this to cause a
denial of service (paravirtualized device unavailability). (CVE-2023-34324)

Zheng Wang discovered a use-after-free in the Renesas Ethernet AVB driver
in the Linux kernel during device removal. A privileged attacker could use
this to cause a denial of service (system crash). (CVE-2023-35827)

Tom Dohrmann discovered that the Secure Encrypted Virtualization (SEV)
implementation for AMD processors in the Linux kernel contained a race
condition when accessing MMIO registers. A local attacker in a SEV guest VM
could possibly use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-46813)

It was discovered that the io_uring subsystem in the Linux kernel contained
a race condition, leading to a null pointer dereference vulnerability. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-46862)

It was discovered that the netfilter subsystem in the Linux kernel did not
properly validate inner tunnel netlink attributes, leading to a null
pointer dereference vulnerability. A local attacker could use this to cause
a denial of service (system crash). (CVE-2023-5972)

It was discovered that the TLS subsystem in the Linux kernel did not
properly perform cryptographic operations in some situations, leading to a
null pointer dereference vulnerability. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-6176)

Jann Horn discovered that a race condition existed in the Linux kernel when
handling io_uring over sockets, leading to a use-after-free vulnerability.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-6531)

Xingyuan Mo discovered that the netfilter subsystem in the Linux kernel did
not properly handle dynset expressions passed from userspace, leading to a
null pointer dereference vulnerability. A local attacker could use this to
cause a denial of service (system crash). (CVE-2023-6622)

It was discovered that the TIPC protocol implementation in the Linux kernel
did not properly handle locking during tipc_crypto_key_revoke() operations.
A local attacker could use this to cause a denial of service (kernel
deadlock). (CVE-2024-0641)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-hwe-6.5, linux-laptop, linux-lowlatency, linux-lowlatency-hwe-6.5, linux-oem-6.5, linux-oracle, linux-raspi, linux-starfive' package(s) on Ubuntu 22.04, Ubuntu 23.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1014-oem", ver:"6.5.0-1014.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-17-generic", ver:"6.5.0-17.17~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-17-generic-64k", ver:"6.5.0-17.17~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-17-lowlatency", ver:"6.5.0-17.17.1.1.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-17-lowlatency-64k", ver:"6.5.0-17.17.1.1.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-22.04", ver:"6.5.0.17.17~22.04.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-22.04", ver:"6.5.0.17.17~22.04.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"6.5.0.17.17.1.1.1~22.04.6", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"6.5.0.17.17.1.1.1~22.04.6", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04d", ver:"6.5.0.1014.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-22.04", ver:"6.5.0.17.17~22.04.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1007-starfive", ver:"6.5.0-1007.8", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1009-laptop", ver:"6.5.0-1009.12", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1010-raspi", ver:"6.5.0-1010.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1013-aws", ver:"6.5.0-1013.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1013-gcp", ver:"6.5.0-1013.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1015-oracle", ver:"6.5.0-1015.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-17-generic", ver:"6.5.0-17.17", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-17-generic-64k", ver:"6.5.0-17.17", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-17-lowlatency", ver:"6.5.0-17.17.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-17-lowlatency-64k", ver:"6.5.0-17.17.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.5.0.1013.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.5.0.1013.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.5.0.17.19", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.5.0.17.19", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.5.0.17.19", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.5.0.17.19", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-laptop-23.10", ver:"6.5.0.1009.12", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.5.0.17.17.14", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.5.0.17.17.14", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.5.0.1015.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.5.0.1010.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"6.5.0.1010.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-starfive", ver:"6.5.0.1007.9", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.5.0.17.19", rls:"UBUNTU23.10"))) {
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
