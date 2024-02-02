# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6604.2");
  script_cve_id("CVE-2023-1079", "CVE-2023-20588", "CVE-2023-45863", "CVE-2023-6606", "CVE-2023-6931", "CVE-2023-6932");
  script_tag(name:"creation_date", value:"2024-01-30 04:08:49 +0000 (Tue, 30 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-08 17:15:07 +0000 (Fri, 08 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6604-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6604-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6604-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-4.15' package(s) announced via the USN-6604-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ASUS HID driver in the Linux kernel did not
properly handle device removal, leading to a use-after-free vulnerability.
A local attacker with physical access could plug in a specially crafted USB
device to cause a denial of service (system crash). (CVE-2023-1079)

Jana Hofmann, Emanuele Vannacci, Cedric Fournet, Boris Kopf, and Oleksii
Oleksenko discovered that some AMD processors could leak stale data from
division operations in certain situations. A local attacker could possibly
use this to expose sensitive information. (CVE-2023-20588)

It was discovered that a race condition existed in the Linux kernel when
performing operations with kernel objects, leading to an out-of-bounds
write. A local attacker could use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2023-45863)

It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly validate the server frame size in certain
situation, leading to an out-of-bounds read vulnerability. An attacker
could use this to construct a malicious CIFS image that, when operated on,
could cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2023-6606)

Budimir Markovic, Lucas De Marchi, and Pengfei Xu discovered that the perf
subsystem in the Linux kernel did not properly validate all event sizes
when attaching new events, leading to an out-of-bounds write vulnerability.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-6931)

It was discovered that the IGMP protocol implementation in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-6932)");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-4.15' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1173-azure", ver:"4.15.0-1173.188~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1173.139", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1173-azure", ver:"4.15.0-1173.188~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1173.157", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1173-azure", ver:"4.15.0-1173.188", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-18.04", ver:"4.15.0.1173.141", rls:"UBUNTU18.04 LTS"))) {
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
