# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6340.2");
  script_cve_id("CVE-2023-2002", "CVE-2023-21255", "CVE-2023-2163", "CVE-2023-2269", "CVE-2023-31084", "CVE-2023-3268", "CVE-2023-35823", "CVE-2023-35824", "CVE-2023-35828");
  script_tag(name:"creation_date", value:"2023-09-11 04:08:35 +0000 (Mon, 11 Sep 2023)");
  script_version("2023-09-25T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-25 05:05:21 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-22 02:02:00 +0000 (Fri, 22 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6340-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6340-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6340-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-5.4, linux-gcp-5.4, linux-gkeop, linux-raspi, linux-raspi-5.4, linux-xilinx-zynqmp' package(s) announced via the USN-6340-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ruihan Li discovered that the bluetooth subsystem in the Linux kernel did
not properly perform permissions checks when handling HCI sockets. A
physically proximate attacker could use this to cause a denial of service
(bluetooth communication). (CVE-2023-2002)

Zi Fan Tan discovered that the binder IPC implementation in the Linux
kernel contained a use-after-free vulnerability. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-21255)

Juan Jose Lopez Jaimez, Meador Inge, Simon Scannell, and Nenad Stojanovski
discovered that the BPF verifier in the Linux kernel did not properly mark
registers for precision tracking in certain situations, leading to an out-
of-bounds access vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-2163)

Zheng Zhang discovered that the device-mapper implementation in the Linux
kernel did not properly handle locking during table_clear() operations. A
local attacker could use this to cause a denial of service (kernel
deadlock). (CVE-2023-2269)

It was discovered that the DVB Core driver in the Linux kernel did not
properly handle locking events in certain situations. A local attacker
could use this to cause a denial of service (kernel deadlock).
(CVE-2023-31084)

It was discovered that the kernel->user space relay implementation in the
Linux kernel did not properly perform certain buffer calculations, leading
to an out-of-bounds read vulnerability. A local attacker could use this to
cause a denial of service (system crash) or expose sensitive information
(kernel memory). (CVE-2023-3268)

It was discovered that the video4linux driver for Philips based TV cards in
the Linux kernel contained a race condition during device removal, leading
to a use-after-free vulnerability. A physically proximate attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-35823)

It was discovered that the SDMC DM1105 PCI device driver in the Linux
kernel contained a race condition during device removal, leading to a use-
after-free vulnerability. A physically proximate attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-35824)

It was discovered that the Renesas USB controller driver in the Linux
kernel contained a race condition during device removal, leading to a use-
after-free vulnerability. A privileged attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-35828)");

  script_tag(name:"affected", value:"'linux-azure-5.4, linux-gcp-5.4, linux-gkeop, linux-raspi, linux-raspi-5.4, linux-xilinx-zynqmp' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1093-raspi", ver:"5.4.0-1093.104~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1112-gcp", ver:"5.4.0-1112.121~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1115-azure", ver:"5.4.0-1115.122~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.4.0.1115.88", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.4.0.1112.88", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1093.90", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1029-xilinx-zynqmp", ver:"5.4.0-1029.33", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1076-gkeop", ver:"5.4.0-1076.80", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1093-raspi", ver:"5.4.0-1093.104", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.4.0.1076.74", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.4", ver:"5.4.0.1076.74", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.4.0.1093.123", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1093.123", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.4.0.1093.123", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2-hwe-18.04", ver:"5.4.0.1093.123", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"5.4.0.1029.31", rls:"UBUNTU20.04 LTS"))) {
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
