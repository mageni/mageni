# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6466.1");
  script_cve_id("CVE-2022-45886", "CVE-2022-45887", "CVE-2022-45919", "CVE-2022-48425", "CVE-2023-1206", "CVE-2023-20569", "CVE-2023-20588", "CVE-2023-21264", "CVE-2023-2156", "CVE-2023-31083", "CVE-2023-3212", "CVE-2023-34319", "CVE-2023-3772", "CVE-2023-38427", "CVE-2023-38430", "CVE-2023-38431", "CVE-2023-38432", "CVE-2023-3863", "CVE-2023-3865", "CVE-2023-3866", "CVE-2023-3867", "CVE-2023-40283", "CVE-2023-4128", "CVE-2023-4132", "CVE-2023-4134", "CVE-2023-4155", "CVE-2023-4194", "CVE-2023-4244", "CVE-2023-4273", "CVE-2023-42752", "CVE-2023-42753", "CVE-2023-42755", "CVE-2023-42756", "CVE-2023-44466", "CVE-2023-4569", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4881", "CVE-2023-4921", "CVE-2023-5197");
  script_tag(name:"creation_date", value:"2023-11-01 13:52:44 +0000 (Wed, 01 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-27 16:09:38 +0000 (Thu, 27 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6466-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6466-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6466-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-nvidia-6.2' package(s) announced via the USN-6466-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hyunwoo Kim discovered that the DVB Core driver in the Linux kernel
contained a race condition during device removal, leading to a use-after-
free vulnerability. A physically proximate attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-45886, CVE-2022-45919)

Hyunwoo Kim discovered that the Technotrend/Hauppauge USB DEC driver in the
Linux kernel did not properly handle device removal events. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2022-45887)

It was discovered that the NTFS file system implementation in the Linux
kernel did not properly validate MFT flags in certain situations. An
attacker could use this to construct a malicious NTFS image that, when
mounted and operated on, could cause a denial of service (system crash).
(CVE-2022-48425)

It was discovered that the IPv6 implementation in the Linux kernel
contained a high rate of hash collisions in connection lookup table. A
remote attacker could use this to cause a denial of service (excessive CPU
consumption). (CVE-2023-1206)

Daniel Trujillo, Johannes Wikner, and Kaveh Razavi discovered that some AMD
processors utilising speculative execution and branch prediction may allow
unauthorised memory reads via a speculative side-channel attack. A local
attacker could use this to expose sensitive information, including kernel
memory. (CVE-2023-20569)

Jana Hofmann, Emanuele Vannacci, Cedric Fournet, Boris Kopf, and Oleksii
Oleksenko discovered that some AMD processors could leak stale data from
division operations in certain situations. A local attacker could possibly
use this to expose sensitive information. (CVE-2023-20588)

It was discovered that the ARM64 KVM implementation in the Linux kernel did
not properly restrict hypervisor memory access. An attacker in a guest VM
could use this to execute arbitrary code in the host OS. (CVE-2023-21264)

It was discovered that the IPv6 RPL protocol implementation in the Linux
kernel did not properly handle user-supplied data. A remote attacker could
use this to cause a denial of service (system crash). (CVE-2023-2156)

Yu Hao and Weiteng Chen discovered that the Bluetooth HCI UART driver in
the Linux kernel contained a race condition, leading to a null pointer
dereference vulnerability. A local attacker could use this to cause a
denial of service (system crash). (CVE-2023-31083)

Yang Lan discovered that the GFS2 file system implementation in the Linux
kernel could attempt to dereference a null pointer in some situations. An
attacker could use this to construct a malicious GFS2 image that, when
mounted and operated on, could cause a denial of service (system crash).
(CVE-2023-3212)

Ross Lagerwall discovered that the Xen netback backend driver in the Linux
kernel did not properly handle certain unusual packets from a
paravirtualized network frontend, leading to a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-nvidia-6.2' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1011-nvidia", ver:"6.2.0-1011.11", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1011-nvidia-64k", ver:"6.2.0-1011.11", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-6.2", ver:"6.2.0.1011.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-6.2", ver:"6.2.0.1011.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-hwe-22.04", ver:"6.2.0.1011.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-hwe-22.04", ver:"6.2.0.1011.13", rls:"UBUNTU22.04 LTS"))) {
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
