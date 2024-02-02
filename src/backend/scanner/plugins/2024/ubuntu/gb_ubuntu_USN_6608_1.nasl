# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6608.1");
  script_cve_id("CVE-2023-6606", "CVE-2023-6817", "CVE-2023-6931", "CVE-2023-6932", "CVE-2024-0193");
  script_tag(name:"creation_date", value:"2024-01-26 04:09:26 +0000 (Fri, 26 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-18 15:15:10 +0000 (Mon, 18 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6608-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6608-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6608-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-6.2, linux-azure, linux-azure-6.2, linux-azure-fde-6.2, linux-gcp, linux-hwe-6.5, linux-laptop, linux-lowlatency, linux-lowlatency-hwe-6.5, linux-oem-6.5, linux-oracle, linux-raspi, linux-starfive' package(s) announced via the USN-6608-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly validate the server frame size in certain
situation, leading to an out-of-bounds read vulnerability. An attacker
could use this to construct a malicious CIFS image that, when operated on,
could cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2023-6606)

Xingyuan Mo discovered that the netfilter subsystem in the Linux kernel did
not properly handle inactive elements in its PIPAPO data structure, leading
to a use-after-free vulnerability. A local attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-6817)

Budimir Markovic, Lucas De Marchi, and Pengfei Xu discovered that the perf
subsystem in the Linux kernel did not properly validate all event sizes
when attaching new events, leading to an out-of-bounds write vulnerability.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-6931)

It was discovered that the IGMP protocol implementation in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-6932)

Kevin Rich discovered that the netfilter subsystem in the Linux kernel did
not properly check deactivated elements in certain situations, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2024-0193)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-6.2, linux-azure, linux-azure-6.2, linux-azure-fde-6.2, linux-gcp, linux-hwe-6.5, linux-laptop, linux-lowlatency, linux-lowlatency-hwe-6.5, linux-oem-6.5, linux-oracle, linux-raspi, linux-starfive' package(s) on Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1018-aws", ver:"6.2.0-1018.18~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1019-azure", ver:"6.2.0-1019.19~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1019-azure-fde", ver:"6.2.0-1019.19~22.04.1.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1013-oem", ver:"6.5.0-1013.14", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-15-generic", ver:"6.5.0-15.15~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-15-generic-64k", ver:"6.5.0-15.15~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-15-lowlatency", ver:"6.5.0-15.15.1.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-15-lowlatency-64k", ver:"6.5.0-15.15.1.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.2.0.1018.18~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.2.0.1019.19~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.2.0.1019.19~22.04.1.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-22.04", ver:"6.5.0.15.15~22.04.8", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-22.04", ver:"6.5.0.15.15~22.04.8", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"6.5.0.15.15.1.1~22.04.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"6.5.0.15.15.1.1~22.04.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04d", ver:"6.5.0.1013.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-22.04", ver:"6.5.0.15.15~22.04.8", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1006-starfive", ver:"6.5.0-1006.7", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1008-laptop", ver:"6.5.0-1008.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1009-raspi", ver:"6.5.0-1009.12", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1011-azure", ver:"6.5.0-1011.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1011-azure-fde", ver:"6.5.0-1011.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1011-gcp", ver:"6.5.0-1011.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1012-aws", ver:"6.5.0-1012.12", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1014-oracle", ver:"6.5.0-1014.14", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-15-generic", ver:"6.5.0-15.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-15-generic-64k", ver:"6.5.0-15.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-15-lowlatency", ver:"6.5.0-15.15.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-15-lowlatency-64k", ver:"6.5.0-15.15.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.5.0.1012.12", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.5.0.1011.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.5.0.1011.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.5.0.1011.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.5.0.15.17", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.5.0.15.17", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.5.0.15.17", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.5.0.15.17", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-laptop-23.10", ver:"6.5.0.1008.11", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.5.0.15.15.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.5.0.15.15.13", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.5.0.1014.14", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.5.0.1009.10", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"6.5.0.1009.10", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-starfive", ver:"6.5.0.1006.8", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.5.0.15.17", rls:"UBUNTU23.10"))) {
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
