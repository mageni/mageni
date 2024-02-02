# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6548.1");
  script_cve_id("CVE-2023-3006", "CVE-2023-37453", "CVE-2023-39189", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-42754", "CVE-2023-5178", "CVE-2023-5717", "CVE-2023-6176");
  script_tag(name:"creation_date", value:"2023-12-12 04:08:54 +0000 (Tue, 12 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-15 17:15:08 +0000 (Mon, 15 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6548-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6548-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6548-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-bluefield, linux-gcp, linux-gcp-5.4, linux-hwe-5.4, linux-ibm, linux-ibm-5.4, linux-kvm, linux-xilinx-zynqmp' package(s) announced via the USN-6548-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Spectre-BHB mitigations were missing for Ampere
processors. A local attacker could potentially use this to expose sensitive
information. (CVE-2023-3006)

It was discovered that the USB subsystem in the Linux kernel contained a
race condition while handling device descriptors in certain situations,
leading to a out-of-bounds read vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2023-37453)

Lucas Leong discovered that the netfilter subsystem in the Linux kernel did
not properly validate some attributes passed from userspace. A local
attacker could use this to cause a denial of service (system crash) or
possibly expose sensitive information (kernel memory). (CVE-2023-39189)

Sunjoo Park discovered that the netfilter subsystem in the Linux kernel did
not properly validate u32 packets content, leading to an out-of-bounds read
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-39192)

Lucas Leong discovered that the netfilter subsystem in the Linux kernel did
not properly validate SCTP data, leading to an out-of-bounds read
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-39193)

Lucas Leong discovered that the Netlink Transformation (XFRM) subsystem in
the Linux kernel did not properly handle state filters, leading to an out-
of-bounds read vulnerability. A privileged local attacker could use this to
cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2023-39194)

Kyle Zeng discovered that the IPv4 implementation in the Linux kernel did
not properly handle socket buffers (skb) when performing IP routing in
certain circumstances, leading to a null pointer dereference vulnerability.
A privileged attacker could use this to cause a denial of service (system
crash). (CVE-2023-42754)

Alon Zahavi discovered that the NVMe-oF/TCP subsystem in the Linux kernel
did not properly handle queue initialization failures in certain
situations, leading to a use-after-free vulnerability. A remote attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-5178)

Budimir Markovic discovered that the perf subsystem in the Linux kernel did
not properly handle event groups, leading to an out-of-bounds write
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-5717)

It was discovered that the TLS subsystem in the Linux kernel did not
properly perform cryptographic operations in some situations, leading to a
null pointer dereference vulnerability. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-6176)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-bluefield, linux-gcp, linux-gcp-5.4, linux-hwe-5.4, linux-ibm, linux-ibm-5.4, linux-kvm, linux-xilinx-zynqmp' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1063-ibm", ver:"5.4.0-1063.68~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1116-aws", ver:"5.4.0-1116.126~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1120-gcp", ver:"5.4.0-1120.129~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1121-azure", ver:"5.4.0-1121.128~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-169-generic", ver:"5.4.0-169.187~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-169-lowlatency", ver:"5.4.0-169.187~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.4.0.1116.94", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.4.0.1121.94", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.4.0.1120.96", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.4.0.169.187~18.04.137", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.4.0.1063.73", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.4.0.169.187~18.04.137", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.169.187~18.04.137", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.169.187~18.04.137", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"5.4.0.169.187~18.04.137", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.4.0.169.187~18.04.137", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1035-xilinx-zynqmp", ver:"5.4.0-1035.39", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1063-ibm", ver:"5.4.0-1063.68", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1076-bluefield", ver:"5.4.0-1076.82", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1104-kvm", ver:"5.4.0-1104.111", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1116-aws", ver:"5.4.0-1116.126", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1120-gcp", ver:"5.4.0-1120.129", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1121-azure", ver:"5.4.0-1121.128", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-169-generic", ver:"5.4.0-169.187", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-169-generic-lpae", ver:"5.4.0-169.187", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-169-lowlatency", ver:"5.4.0-169.187", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-20.04", ver:"5.4.0.1116.113", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-20.04", ver:"5.4.0.1121.114", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-bluefield", ver:"5.4.0.1076.71", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-20.04", ver:"5.4.0.1120.122", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.4.0.169.167", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.4.0.169.167", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm-lts-20.04", ver:"5.4.0.1063.92", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.4.0.1104.100", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.4.0.169.167", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.169.167", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.169.167", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.4.0.169.167", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"5.4.0.1035.35", rls:"UBUNTU20.04 LTS"))) {
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
