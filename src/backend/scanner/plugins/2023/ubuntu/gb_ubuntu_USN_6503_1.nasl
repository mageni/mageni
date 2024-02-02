# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6503.1");
  script_cve_id("CVE-2023-31085", "CVE-2023-4244", "CVE-2023-5090", "CVE-2023-5345", "CVE-2023-5633");
  script_tag(name:"creation_date", value:"2023-11-22 04:08:57 +0000 (Wed, 22 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-02 20:48:33 +0000 (Thu, 02 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6503-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6503-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6503-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-laptop, linux-lowlatency, linux-oem-6.5, linux-oracle, linux-raspi, linux-starfive' package(s) announced via the USN-6503-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yu Hao discovered that the UBI driver in the Linux kernel did not properly
check for MTD with zero erasesize during device attachment. A local
privileged attacker could use this to cause a denial of service (system
crash). (CVE-2023-31085)

Bien Pham discovered that the netfiler subsystem in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local user could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-4244)

Maxim Levitsky discovered that the KVM nested virtualization (SVM)
implementation for AMD processors in the Linux kernel did not properly
handle x2AVIC MSRs. An attacker in a guest VM could use this to cause a
denial of service (host kernel crash). (CVE-2023-5090)

It was discovered that the SMB network file sharing protocol implementation
in the Linux kernel did not properly handle certain error conditions,
leading to a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-5345)

Murray McAllister discovered that the VMware Virtual GPU DRM driver in the
Linux kernel did not properly handle memory objects when storing surfaces,
leading to a use-after-free vulnerability. A local attacker in a guest VM
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-5633)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-laptop, linux-lowlatency, linux-oem-6.5, linux-oracle, linux-raspi, linux-starfive' package(s) on Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1008-oem", ver:"6.5.0-1008.8", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04d", ver:"6.5.0.1008.10", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1004-starfive", ver:"6.5.0-1004.5", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1006-laptop", ver:"6.5.0-1006.9", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1007-raspi", ver:"6.5.0-1007.9", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1010-aws", ver:"6.5.0-1010.10", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1012-oracle", ver:"6.5.0-1012.12", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-13-generic", ver:"6.5.0-13.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-13-generic-64k", ver:"6.5.0-13.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-13-lowlatency", ver:"6.5.0-13.13.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-13-lowlatency-64k", ver:"6.5.0-13.13.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.5.0.1010.10", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.5.0.13.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.5.0.13.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.5.0.13.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.5.0.13.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-laptop-23.10", ver:"6.5.0.1006.9", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.5.0.13.13.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.5.0.13.13.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.5.0.1012.12", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.5.0.1007.8", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"6.5.0.1007.8", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-starfive", ver:"6.5.0.1004.6", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.5.0.13.15", rls:"UBUNTU23.10"))) {
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
