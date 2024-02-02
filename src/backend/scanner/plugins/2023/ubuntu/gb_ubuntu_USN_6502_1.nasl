# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6502.1");
  script_cve_id("CVE-2023-25775", "CVE-2023-31085", "CVE-2023-45871", "CVE-2023-5090", "CVE-2023-5345");
  script_tag(name:"creation_date", value:"2023-11-22 04:08:57 +0000 (Wed, 22 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 20:10:37 +0000 (Thu, 17 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6502-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6502-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6502-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-6.2, linux-hwe-6.2, linux-kvm, linux-lowlatency, linux-lowlatency-hwe-6.2, linux-raspi, linux-starfive' package(s) announced via the USN-6502-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ivan D Barrera, Christopher Bednarz, Mustafa Ismail, and Shiraz Saleem
discovered that the InfiniBand RDMA driver in the Linux kernel did not
properly check for zero-length STAG or MR registration. A remote attacker
could possibly use this to execute arbitrary code. (CVE-2023-25775)

Yu Hao discovered that the UBI driver in the Linux kernel did not properly
check for MTD with zero erasesize during device attachment. A local
privileged attacker could use this to cause a denial of service (system
crash). (CVE-2023-31085)

Manfred Rudigier discovered that the Intel(R) PCI-Express Gigabit (igb)
Ethernet driver in the Linux kernel did not properly validate received
frames that are larger than the set MTU size, leading to a buffer overflow
vulnerability. An attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-45871)

Maxim Levitsky discovered that the KVM nested virtualization (SVM)
implementation for AMD processors in the Linux kernel did not properly
handle x2AVIC MSRs. An attacker in a guest VM could use this to cause a
denial of service (host kernel crash). (CVE-2023-5090)

It was discovered that the SMB network file sharing protocol implementation
in the Linux kernel did not properly handle certain error conditions,
leading to a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-5345)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-6.2, linux-hwe-6.2, linux-kvm, linux-lowlatency, linux-lowlatency-hwe-6.2, linux-raspi, linux-starfive' package(s) on Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1016-aws", ver:"6.2.0-1016.16~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1017-lowlatency", ver:"6.2.0-1017.17~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1017-lowlatency-64k", ver:"6.2.0-1017.17~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-37-generic", ver:"6.2.0-37.38~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-37-generic-64k", ver:"6.2.0-37.38~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-37-generic-lpae", ver:"6.2.0-37.38~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.2.0.1016.16~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-22.04", ver:"6.2.0.37.38~22.04.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-22.04", ver:"6.2.0.37.38~22.04.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-22.04", ver:"6.2.0.37.38~22.04.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"6.2.0.1017.17~22.04.14", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"6.2.0.1017.17~22.04.14", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-22.04", ver:"6.2.0.37.38~22.04.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1009-starfive", ver:"6.2.0-1009.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1016-aws", ver:"6.2.0-1016.16", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1017-kvm", ver:"6.2.0-1017.17", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1017-lowlatency", ver:"6.2.0-1017.17", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1017-lowlatency-64k", ver:"6.2.0-1017.17", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1017-raspi", ver:"6.2.0-1017.19", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-37-generic", ver:"6.2.0-37.38", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-37-generic-64k", ver:"6.2.0-37.38", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-37-generic-lpae", ver:"6.2.0-37.38", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.2.0.1016.17", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.2.0.37.37", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.2.0.37.37", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.2.0.37.37", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.2.0.1017.17", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.2.0.1017.17", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.2.0.1017.17", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.2.0.1017.20", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"6.2.0.1017.20", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-starfive", ver:"6.2.0.1009.12", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.2.0.37.37", rls:"UBUNTU23.04"))) {
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
