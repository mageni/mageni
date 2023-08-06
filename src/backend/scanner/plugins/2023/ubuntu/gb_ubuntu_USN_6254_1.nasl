# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6254.1");
  script_cve_id("CVE-2023-0458", "CVE-2023-1611", "CVE-2023-2124", "CVE-2023-2162", "CVE-2023-2513", "CVE-2023-3090", "CVE-2023-3141", "CVE-2023-3159", "CVE-2023-3161", "CVE-2023-3268", "CVE-2023-3390", "CVE-2023-35001");
  script_tag(name:"creation_date", value:"2023-07-27 04:09:33 +0000 (Thu, 27 Jul 2023)");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-12 16:49:00 +0000 (Wed, 12 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6254-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6254-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6254-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) announced via the USN-6254-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jordy Zomer and Alexandra Sandulescu discovered that syscalls invoking the
do_prlimit() function in the Linux kernel did not properly handle
speculative execution barriers. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2023-0458)

It was discovered that a race condition existed in the btrfs file system
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-1611)

It was discovered that the XFS file system implementation in the Linux
kernel did not properly perform metadata validation when mounting certain
images. An attacker could use this to specially craft a file system image
that, when mounted, could cause a denial of service (system crash).
(CVE-2023-2124)

It was discovered that a use-after-free vulnerability existed in the iSCSI
TCP implementation in the Linux kernel. A local attacker could possibly use
this to cause a denial of service (system crash). (CVE-2023-2162)

It was discovered that the ext4 file system implementation in the Linux
kernel did not properly handle extra inode size for extended attributes,
leading to a use-after-free vulnerability. A privileged attacker could
possibly use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-2513)

It was discovered that the IP-VLAN network driver for the Linux kernel did
not properly initialize memory in some situations, leading to an out-of-
bounds write vulnerability. An attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2023-3090)

It was discovered that the Ricoh R5C592 MemoryStick card reader driver in
the Linux kernel contained a race condition during module unload, leading
to a use-after-free vulnerability. A local attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-3141)

It was discovered that a use-after-free vulnerability existed in the IEEE
1394 (Firewire) implementation in the Linux kernel. A privileged attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-3159)

Sanan Hasanov discovered that the framebuffer console driver in the Linux
kernel did not properly perform checks for font dimension limits. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-3161)

It was discovered that the kernel->user space relay implementation in the
Linux kernel did not properly perform certain buffer calculations, leading
to an out-of-bounds read vulnerability. A local attacker could use this to
cause a denial of service (system crash) or expose sensitive information
(kernel memory). (CVE-2023-3268)

It was discovered that the netfilter subsystem in the Linux kernel did ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1121-aws", ver:"4.4.0-1121.127", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-243-generic", ver:"4.4.0-243.277~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-243-lowlatency", ver:"4.4.0-243.277~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1121.118", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.243.211", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.243.211", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.243.211", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1122-kvm", ver:"4.4.0-1122.132", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1159-aws", ver:"4.4.0-1159.174", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-243-generic", ver:"4.4.0-243.277", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-243-lowlatency", ver:"4.4.0-243.277", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1159.163", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.243.249", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.243.249", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1122.119", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.243.249", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.243.249", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.243.249", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.243.249", rls:"UBUNTU16.04 LTS"))) {
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
