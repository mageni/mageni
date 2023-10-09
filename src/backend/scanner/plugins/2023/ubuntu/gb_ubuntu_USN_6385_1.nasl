# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6385.1");
  script_cve_id("CVE-2022-27672", "CVE-2022-4269", "CVE-2023-0458", "CVE-2023-1075", "CVE-2023-1076", "CVE-2023-1206", "CVE-2023-1380", "CVE-2023-1611", "CVE-2023-2002", "CVE-2023-20593", "CVE-2023-2162", "CVE-2023-2163", "CVE-2023-2235", "CVE-2023-2269", "CVE-2023-28328", "CVE-2023-28466", "CVE-2023-2898", "CVE-2023-3090", "CVE-2023-3141", "CVE-2023-31436", "CVE-2023-3220", "CVE-2023-32269", "CVE-2023-3390", "CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3777", "CVE-2023-3863", "CVE-2023-3995", "CVE-2023-4004", "CVE-2023-4015", "CVE-2023-40283", "CVE-2023-4128", "CVE-2023-4194", "CVE-2023-4273", "CVE-2023-4569");
  script_tag(name:"creation_date", value:"2023-09-20 04:08:41 +0000 (Wed, 20 Sep 2023)");
  script_version("2023-09-25T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-25 05:05:21 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-22 02:02:00 +0000 (Fri, 22 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6385-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6385-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6385-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.0' package(s) announced via the USN-6385-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that some AMD x86-64 processors with SMT enabled could
speculatively execute instructions using a return address from a sibling
thread. A local attacker could possibly use this to expose sensitive
information. (CVE-2022-27672)

William Zhao discovered that the Traffic Control (TC) subsystem in the
Linux kernel did not properly handle network packet retransmission in
certain situations. A local attacker could use this to cause a denial of
service (kernel deadlock). (CVE-2022-4269)

Jordy Zomer and Alexandra Sandulescu discovered that syscalls invoking the
do_prlimit() function in the Linux kernel did not properly handle
speculative execution barriers. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2023-0458)

It was discovered that the TLS subsystem in the Linux kernel contained a
type confusion vulnerability in some situations. A local attacker could use
this to cause a denial of service (system crash) or possibly expose
sensitive information. (CVE-2023-1075)

It was discovered that the TUN/TAP driver in the Linux kernel did not
properly initialize socket data. A local attacker could use this to cause a
denial of service (system crash). (CVE-2023-1076, CVE-2023-4194)

It was discovered that the IPv6 implementation in the Linux kernel
contained a high rate of hash collisions in connection lookup table. A
remote attacker could use this to cause a denial of service (excessive CPU
consumption). (CVE-2023-1206)

It was discovered that the Broadcom FullMAC USB WiFi driver in the Linux
kernel did not properly perform data buffer size validation in some
situations. A physically proximate attacker could use this to craft a
malicious USB device that when inserted, could cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-1380)

It was discovered that a race condition existed in the btrfs file system
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-1611)

Ruihan Li discovered that the bluetooth subsystem in the Linux kernel did
not properly perform permissions checks when handling HCI sockets. A
physically proximate attacker could use this to cause a denial of service
(bluetooth communication). (CVE-2023-2002)

Tavis Ormandy discovered that some AMD processors did not properly handle
speculative execution of certain vector register instructions. A local
attacker could use this to expose sensitive information. (CVE-2023-20593)

It was discovered that a use-after-free vulnerability existed in the iSCSI
TCP implementation in the Linux kernel. A local attacker could possibly use
this to cause a denial of service (system crash). (CVE-2023-2162)

Juan Jose Lopez Jaimez, Meador Inge, Simon Scannell, and Nenad Stojanovski
discovered that ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.0.0-1021-oem", ver:"6.0.0-1021.21", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04b", ver:"6.0.0.1021.21", rls:"UBUNTU22.04 LTS"))) {
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
