# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6343.1");
  script_cve_id("CVE-2023-1206", "CVE-2023-34319", "CVE-2023-40283", "CVE-2023-4128", "CVE-2023-4155", "CVE-2023-4194", "CVE-2023-4273");
  script_tag(name:"creation_date", value:"2023-09-07 04:08:46 +0000 (Thu, 07 Sep 2023)");
  script_version("2023-09-07T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-07 05:05:21 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-16 20:32:00 +0000 (Wed, 16 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6343-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6343-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6343-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.1' package(s) announced via the USN-6343-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the IPv6 implementation in the Linux kernel
contained a high rate of hash collisions in connection lookup table. A
remote attacker could use this to cause a denial of service (excessive CPU
consumption). (CVE-2023-1206)

Ross Lagerwall discovered that the Xen netback backend driver in the Linux
kernel did not properly handle certain unusual packets from a
paravirtualized network frontend, leading to a buffer overflow. An attacker
in a guest VM could use this to cause a denial of service (host system
crash) or possibly execute arbitrary code. (CVE-2023-34319)

It was discovered that the bluetooth subsystem in the Linux kernel did not
properly handle L2CAP socket release, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-40283)

It was discovered that some network classifier implementations in the Linux
kernel contained use-after-free vulnerabilities. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-4128)

Andy Nguyen discovered that the KVM implementation for AMD processors in
the Linux kernel with Secure Encrypted Virtualization (SEV) contained a
race condition when accessing the GHCB page. A local attacker in a SEV
guest VM could possibly use this to cause a denial of service (host system
crash). (CVE-2023-4155)

It was discovered that the TUN/TAP driver in the Linux kernel did not
properly initialize socket data. A local attacker could use this to cause a
denial of service (system crash). (CVE-2023-4194)

Maxim Suhanov discovered that the exFAT file system implementation in the
Linux kernel did not properly check a file name length, leading to an out-
of-bounds write vulnerability. An attacker could use this to construct a
malicious exFAT image that, when mounted and operated on, could cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-4273)");

  script_tag(name:"affected", value:"'linux-oem-6.1' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-1021-oem", ver:"6.1.0-1021.21", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04c", ver:"6.1.0.1021.21", rls:"UBUNTU22.04 LTS"))) {
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
