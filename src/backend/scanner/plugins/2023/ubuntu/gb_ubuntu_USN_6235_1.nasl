# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6235.1");
  script_cve_id("CVE-2022-4842", "CVE-2023-0459", "CVE-2023-0597", "CVE-2023-1073", "CVE-2023-2124", "CVE-2023-2176", "CVE-2023-2430", "CVE-2023-35788");
  script_tag(name:"creation_date", value:"2023-07-19 04:14:28 +0000 (Wed, 19 Jul 2023)");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:00 +0000 (Fri, 23 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-6235-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6235-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6235-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2023577");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2023220");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.0' package(s) announced via the USN-6235-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the NTFS file system implementation in the Linux
kernel contained a null pointer dereference in some situations. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2022-4842)

Jordy Zomer and Alexandra Sandulescu discovered that the Linux kernel did
not properly implement speculative execution barriers in usercopy functions
in certain situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2023-0459)

Seth Jenkins discovered that the CPU data to memory implementation for x86
processors in the Linux kernel did not properly perform address
randomization. A local attacker could use this to expose sensitive
information (kernel memory) or in conjunction with another kernel
vulnerability. (CVE-2023-0597)

It was discovered that the Human Interface Device (HID) support driver in
the Linux kernel contained a type confusion vulnerability in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-1073)

It was discovered that the XFS file system implementation in the Linux
kernel did not properly perform metadata validation when mounting certain
images. An attacker could use this to specially craft a file system image
that, when mounted, could cause a denial of service (system crash).
(CVE-2023-2124)

Wei Chen discovered that the InfiniBand RDMA communication manager
implementation in the Linux kernel contained an out-of-bounds read
vulnerability. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-2176)

Xingyuan Mo and Gengjia Chen discovered that the io_uring subsystem in the
Linux kernel did not properly handle locking when IOPOLL mode is being
used. A local attacker could use this to cause a denial of service (system
crash). (CVE-2023-2430)

Hangyu Hua discovered that the Flower classifier implementation in the
Linux kernel contained an out-of-bounds write vulnerability. An attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-35788, LP: #2023577)

It was discovered that for some Intel processors the INVLPG instruction
implementation did not properly flush global TLB entries when PCIDs are
enabled. An attacker could use this to expose sensitive information
(kernel memory) or possibly cause undesired behaviors. (LP: #2023220)");

  script_tag(name:"affected", value:"'linux-oem-6.0' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.0.0-1019-oem", ver:"6.0.0-1019.19", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04b", ver:"6.0.0.1019.19", rls:"UBUNTU22.04 LTS"))) {
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
