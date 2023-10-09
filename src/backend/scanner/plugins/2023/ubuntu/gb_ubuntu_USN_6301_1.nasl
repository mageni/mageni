# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6301.1");
  script_cve_id("CVE-2020-36691", "CVE-2022-0168", "CVE-2022-1184", "CVE-2022-27672", "CVE-2022-4269", "CVE-2023-0590", "CVE-2023-1611", "CVE-2023-1855", "CVE-2023-1990", "CVE-2023-2124", "CVE-2023-2194", "CVE-2023-28466", "CVE-2023-30772", "CVE-2023-3111", "CVE-2023-3141", "CVE-2023-33203");
  script_tag(name:"creation_date", value:"2023-08-18 04:08:41 +0000 (Fri, 18 Aug 2023)");
  script_version("2023-08-18T05:05:27+0000");
  script_tag(name:"last_modification", value:"2023-08-18 05:05:27 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-09 22:51:00 +0000 (Fri, 09 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-6301-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6301-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6301-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe-5.4, linux-xilinx-zynqmp' package(s) announced via the USN-6301-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the netlink implementation in the Linux kernel did
not properly validate policies when parsing attributes in some situations.
An attacker could use this to cause a denial of service (infinite
recursion). (CVE-2020-36691)

Billy Jheng Bing Jhong discovered that the CIFS network file system
implementation in the Linux kernel did not properly validate arguments to
ioctl() in some situations. A local attacker could possibly use this to
cause a denial of service (system crash). (CVE-2022-0168)

It was discovered that the ext4 file system implementation in the Linux
kernel contained a use-after-free vulnerability. An attacker could use this
to construct a malicious ext4 file system image that, when mounted, could
cause a denial of service (system crash). (CVE-2022-1184)

It was discovered that some AMD x86-64 processors with SMT enabled could
speculatively execute instructions using a return address from a sibling
thread. A local attacker could possibly use this to expose sensitive
information. (CVE-2022-27672)

William Zhao discovered that the Traffic Control (TC) subsystem in the
Linux kernel did not properly handle network packet retransmission in
certain situations. A local attacker could use this to cause a denial of
service (kernel deadlock). (CVE-2022-4269)

It was discovered that a race condition existed in the qdisc implementation
in the Linux kernel, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-0590)

It was discovered that a race condition existed in the btrfs file system
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-1611)

It was discovered that the APM X-Gene SoC hardware monitoring driver in the
Linux kernel contained a race condition, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or expose sensitive information (kernel memory).
(CVE-2023-1855)

It was discovered that the ST NCI NFC driver did not properly handle device
removal events. A physically proximate attacker could use this to cause a
denial of service (system crash). (CVE-2023-1990)

It was discovered that the XFS file system implementation in the Linux
kernel did not properly perform metadata validation when mounting certain
images. An attacker could use this to specially craft a file system image
that, when mounted, could cause a denial of service (system crash).
(CVE-2023-2124)

It was discovered that the SLIMpro I2C device driver in the Linux kernel
did not properly validate user-supplied data in some situations, leading to
an out-of-bounds write vulnerability. A privileged attacker could use this
to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-hwe-5.4, linux-xilinx-zynqmp' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-156-generic", ver:"5.4.0-156.173~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-156-generic-lpae", ver:"5.4.0-156.173~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-156-lowlatency", ver:"5.4.0-156.173~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.4.0.156.173~18.04.126", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-18.04", ver:"5.4.0.156.173~18.04.126", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.4.0.156.173~18.04.126", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.156.173~18.04.126", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.156.173~18.04.126", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"5.4.0.156.173~18.04.126", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.4.0.156.173~18.04.126", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1027-xilinx-zynqmp", ver:"5.4.0-1027.31", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"5.4.0.1027.29", rls:"UBUNTU20.04 LTS"))) {
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
