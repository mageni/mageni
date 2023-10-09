# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6416.2");
  script_cve_id("CVE-2023-1206", "CVE-2023-20569", "CVE-2023-2156", "CVE-2023-3338", "CVE-2023-38432", "CVE-2023-3863", "CVE-2023-3865", "CVE-2023-3866", "CVE-2023-4132", "CVE-2023-4155", "CVE-2023-4194", "CVE-2023-4273", "CVE-2023-44466");
  script_tag(name:"creation_date", value:"2023-10-09 04:08:48 +0000 (Mon, 09 Oct 2023)");
  script_version("2023-10-09T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-10-09 05:05:36 +0000 (Mon, 09 Oct 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-27 16:02:00 +0000 (Thu, 27 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6416-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6416-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6416-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe-5.15, linux-oracle-5.15' package(s) announced via the USN-6416-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the IPv6 implementation in the Linux kernel
contained a high rate of hash collisions in connection lookup table. A
remote attacker could use this to cause a denial of service (excessive CPU
consumption). (CVE-2023-1206)

Daniel Trujillo, Johannes Wikner, and Kaveh Razavi discovered that some AMD
processors utilising speculative execution and branch prediction may allow
unauthorised memory reads via a speculative side-channel attack. A local
attacker could use this to expose sensitive information, including kernel
memory. (CVE-2023-20569)

It was discovered that the IPv6 RPL protocol implementation in the Linux
kernel did not properly handle user-supplied data. A remote attacker could
use this to cause a denial of service (system crash). (CVE-2023-2156)

Davide Ornaghi discovered that the DECnet network protocol implementation
in the Linux kernel contained a null pointer dereference vulnerability. A
remote attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. Please note that kernel support for the
DECnet has been removed to resolve this CVE. (CVE-2023-3338)

Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel
did not properly validate command payload size, leading to a out-of-bounds
read vulnerability. A remote attacker could possibly use this to cause a
denial of service (system crash). (CVE-2023-38432)

It was discovered that the NFC implementation in the Linux kernel contained
a use-after-free vulnerability when performing peer-to-peer communication
in certain conditions. A privileged attacker could use this to cause a
denial of service (system crash) or possibly expose sensitive information
(kernel memory). (CVE-2023-3863)

Laurence Wit discovered that the KSMBD implementation in the Linux kernel
did not properly validate a buffer size in certain situations, leading to
an out-of-bounds read vulnerability. A remote attacker could use this to
cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2023-3865)

Laurence Wit discovered that the KSMBD implementation in the Linux kernel
contained a null pointer dereference vulnerability when handling handling
chained requests. A remote attacker could use this to cause a denial of
service (system crash). (CVE-2023-3866)

It was discovered that the Siano USB MDTV receiver device driver in the
Linux kernel did not properly handle device initialization failures in
certain situations, leading to a use-after-free vulnerability. A physically
proximate attacker could use this cause a denial of service (system crash).
(CVE-2023-4132)

Andy Nguyen discovered that the KVM implementation for AMD processors in
the Linux kernel with Secure Encrypted Virtualization (SEV) contained a
race condition when accessing the GHCB page. A local attacker in a SEV
guest VM could possibly use this to cause a denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-hwe-5.15, linux-oracle-5.15' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1045-oracle", ver:"5.15.0-1045.51~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-86-generic", ver:"5.15.0-86.96~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-86-generic-64k", ver:"5.15.0-86.96~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-86-generic-lpae", ver:"5.15.0-86.96~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-20.04", ver:"5.15.0.86.96~20.04.44", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-20.04", ver:"5.15.0.86.96~20.04.44", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-20.04", ver:"5.15.0.86.96~20.04.44", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.15.0.86.96~20.04.44", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.15.0.86.96~20.04.44", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04c", ver:"5.15.0.86.96~20.04.44", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04d", ver:"5.15.0.86.96~20.04.44", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.15.0.1045.51~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-20.04", ver:"5.15.0.86.96~20.04.44", rls:"UBUNTU20.04 LTS"))) {
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
