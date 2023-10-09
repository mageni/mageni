# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6331.1");
  script_cve_id("CVE-2020-36691", "CVE-2022-0168", "CVE-2022-1184", "CVE-2022-27672", "CVE-2022-40982", "CVE-2022-4269", "CVE-2023-0590", "CVE-2023-1611", "CVE-2023-1855", "CVE-2023-1990", "CVE-2023-20593", "CVE-2023-2124", "CVE-2023-2194", "CVE-2023-28466", "CVE-2023-30772", "CVE-2023-3111", "CVE-2023-3141", "CVE-2023-33203", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776");
  script_tag(name:"creation_date", value:"2023-09-01 04:08:43 +0000 (Fri, 01 Sep 2023)");
  script_version("2023-09-07T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-07 05:05:21 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:26:00 +0000 (Mon, 31 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6331-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6331-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6331-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-6331-1 advisory.");

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

Daniel Moghimi discovered that some Intel(R) Processors did not properly
clear microarchitectural state after speculative execution of various
instructions. A local unprivileged user could use this to obtain to
sensitive information. (CVE-2022-40982)

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

Tavis Ormandy discovered that some AMD processors did not properly handle
speculative execution of certain vector register instructions. A local
attacker could use this to expose sensitive information. (CVE-2023-20593)

It was discovered that the XFS file system implementation in the Linux
kernel did not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1114-azure", ver:"5.4.0-1114.120", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-20.04", ver:"5.4.0.1114.107", rls:"UBUNTU20.04 LTS"))) {
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
