# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6318.1");
  script_cve_id("CVE-2022-40982", "CVE-2023-20593", "CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3777", "CVE-2023-3995", "CVE-2023-4004", "CVE-2023-4015");
  script_tag(name:"creation_date", value:"2023-08-30 04:08:40 +0000 (Wed, 30 Aug 2023)");
  script_version("2023-09-13T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-09-13 05:05:22 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-11 17:59:00 +0000 (Mon, 11 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6318-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6318-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6318-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-6.2, linux-azure, linux-hwe-6.2, linux-ibm, linux-kvm, linux-lowlatency, linux-lowlatency-hwe-6.2, linux-raspi' package(s) announced via the USN-6318-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Moghimi discovered that some Intel(R) Processors did not properly
clear microarchitectural state after speculative execution of various
instructions. A local unprivileged user could use this to obtain to
sensitive information. (CVE-2022-40982)

Tavis Ormandy discovered that some AMD processors did not properly handle
speculative execution of certain vector register instructions. A local
attacker could use this to expose sensitive information. (CVE-2023-20593)

It was discovered that the universal 32bit network packet classifier
implementation in the Linux kernel did not properly perform reference
counting in some situations, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-3609)

It was discovered that the netfilter subsystem in the Linux kernel did not
properly handle certain error conditions, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-3610)

It was discovered that the Quick Fair Queueing network scheduler
implementation in the Linux kernel contained an out-of-bounds write
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-3611)

It was discovered that the network packet classifier with
netfilter/firewall marks implementation in the Linux kernel did not
properly handle reference counting, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-3776)

Kevin Rich discovered that the netfilter subsystem in the Linux kernel did
not properly handle table rules flush in certain circumstances. A local
attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2023-3777)

Kevin Rich discovered that the netfilter subsystem in the Linux kernel did
not properly handle rule additions to bound chains in certain
circumstances. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2023-3995)

It was discovered that the netfilter subsystem in the Linux kernel did not
properly handle PIPAPO element removal, leading to a use-after-free
vulnerability. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2023-4004)

Kevin Rich discovered that the netfilter subsystem in the Linux kernel did
not properly handle bound chain deactivation in certain circumstances. A
local attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2023-4015)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-6.2, linux-azure, linux-hwe-6.2, linux-ibm, linux-kvm, linux-lowlatency, linux-lowlatency-hwe-6.2, linux-raspi' package(s) on Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1010-aws", ver:"6.2.0-1010.10~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1011-lowlatency", ver:"6.2.0-1011.11~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1011-lowlatency-64k", ver:"6.2.0-1011.11~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-31-generic", ver:"6.2.0-31.31~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-31-generic-64k", ver:"6.2.0-31.31~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-31-generic-lpae", ver:"6.2.0-31.31~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.2.0.1010.10~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-22.04", ver:"6.2.0.31.31~22.04.8", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-22.04", ver:"6.2.0.31.31~22.04.8", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-22.04", ver:"6.2.0.31.31~22.04.8", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"6.2.0.1011.11~22.04.8", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"6.2.0.1011.11~22.04.8", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-22.04", ver:"6.2.0.31.31~22.04.8", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1008-ibm", ver:"6.2.0-1008.8", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1010-aws", ver:"6.2.0-1010.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1010-azure", ver:"6.2.0-1010.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1011-kvm", ver:"6.2.0-1011.11", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1011-lowlatency", ver:"6.2.0-1011.11", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1011-lowlatency-64k", ver:"6.2.0-1011.11", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1011-raspi", ver:"6.2.0-1011.13", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-31-generic", ver:"6.2.0-31.31", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-31-generic-64k", ver:"6.2.0-31.31", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-31-generic-lpae", ver:"6.2.0-31.31", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.2.0.1010.11", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.2.0.1010.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.2.0.31.29", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.2.0.31.29", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.2.0.31.29", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"6.2.0.1008.8", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.2.0.1011.11", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.2.0.1011.11", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.2.0.1011.11", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.2.0.1011.14", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"6.2.0.1011.14", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.2.0.31.29", rls:"UBUNTU23.04"))) {
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
