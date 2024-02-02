# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6494.2");
  script_cve_id("CVE-2023-31085", "CVE-2023-39189", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-42754", "CVE-2023-45862", "CVE-2023-45871", "CVE-2023-5717");
  script_tag(name:"creation_date", value:"2023-12-01 04:08:55 +0000 (Fri, 01 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-04 03:24:15 +0000 (Sat, 04 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6494-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6494-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6494-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15' package(s) announced via the USN-6494-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yu Hao discovered that the UBI driver in the Linux kernel did not properly
check for MTD with zero erasesize during device attachment. A local
privileged attacker could use this to cause a denial of service (system
crash). (CVE-2023-31085)

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

It was discovered that the USB ENE card reader driver in the Linux kernel
did not properly allocate enough memory when processing the storage device
boot blocks. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-45862)

Manfred Rudigier discovered that the Intel(R) PCI-Express Gigabit (igb)
Ethernet driver in the Linux kernel did not properly validate received
frames that are larger than the set MTU size, leading to a buffer overflow
vulnerability. An attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-45871)

Budimir Markovic discovered that the perf subsystem in the Linux kernel did
not properly handle event groups, leading to an out-of-bounds write
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-5717)");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1172-azure", ver:"4.15.0-1172.187~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1172.138", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1157-gcp", ver:"4.15.0-1157.174~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1172-azure", ver:"4.15.0-1172.187~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1172.156", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1157.147", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1157.147", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1157-gcp", ver:"4.15.0-1157.174", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1172-azure", ver:"4.15.0-1172.187", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-18.04", ver:"4.15.0.1172.140", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-18.04", ver:"4.15.0.1157.171", rls:"UBUNTU18.04 LTS"))) {
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
