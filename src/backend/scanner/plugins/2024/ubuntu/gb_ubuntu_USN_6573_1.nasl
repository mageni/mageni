# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6573.1");
  script_cve_id("CVE-2023-39189", "CVE-2023-42754", "CVE-2023-45898", "CVE-2023-5158", "CVE-2023-5178", "CVE-2023-5717");
  script_tag(name:"creation_date", value:"2024-01-10 04:09:13 +0000 (Wed, 10 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-15 17:15:08 +0000 (Mon, 15 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU23\.10");

  script_xref(name:"Advisory-ID", value:"USN-6573-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6573-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-6573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lucas Leong discovered that the netfilter subsystem in the Linux kernel did
not properly validate some attributes passed from userspace. A local
attacker could use this to cause a denial of service (system crash) or
possibly expose sensitive information (kernel memory). (CVE-2023-39189)

Kyle Zeng discovered that the IPv4 implementation in the Linux kernel did
not properly handle socket buffers (skb) when performing IP routing in
certain circumstances, leading to a null pointer dereference vulnerability.
A privileged attacker could use this to cause a denial of service (system
crash). (CVE-2023-42754)

Yikebaer Aizezi discovered that the ext4 file system implementation in the
Linux kernel contained a use-after-free vulnerability when handling inode
extent metadata. An attacker could use this to construct a malicious ext4
file system image that, when mounted, could cause a denial of service
(system crash). (CVE-2023-45898)

Jason Wang discovered that the virtio ring implementation in the Linux
kernel did not properly handle iov buffers in some situations. A local
attacker in a guest VM could use this to cause a denial of service (host
system crash). (CVE-2023-5158)

Alon Zahavi discovered that the NVMe-oF/TCP subsystem in the Linux kernel
did not properly handle queue initialization failures in certain
situations, leading to a use-after-free vulnerability. A remote attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-5178)

Budimir Markovic discovered that the perf subsystem in the Linux kernel did
not properly handle event groups, leading to an out-of-bounds write
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-5717)");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 23.10.");

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

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1010-azure", ver:"6.5.0-1010.10", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1010-azure-fde", ver:"6.5.0-1010.10", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.5.0.1010.12", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.5.0.1010.12", rls:"UBUNTU23.10"))) {
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
