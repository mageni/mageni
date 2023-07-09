# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6174.1");
  script_cve_id("CVE-2023-0459", "CVE-2023-1073", "CVE-2023-26606");
  script_tag(name:"creation_date", value:"2023-06-19 04:09:24 +0000 (Mon, 19 Jun 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-04 03:26:00 +0000 (Sat, 04 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6174-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6174-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.17' package(s) announced via the USN-6174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jordy Zomer and Alexandra Sandulescu discovered that the Linux kernel did
not properly implement speculative execution barriers in usercopy functions
in certain situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2023-0459)

It was discovered that the Human Interface Device (HID) support driver in
the Linux kernel contained a type confusion vulnerability in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-1073)

It was discovered that the NTFS file system implementation in the Linux
kernel did not properly handle a loop termination condition, leading to an
out-of-bounds read vulnerability. A local attacker could use this to cause
a denial of service (system crash) or possibly expose sensitive
information. (CVE-2023-26606)");

  script_tag(name:"affected", value:"'linux-oem-5.17' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.17.0-1033-oem", ver:"5.17.0-1033.34", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04", ver:"5.17.0.1033.31", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04a", ver:"5.17.0.1033.31", rls:"UBUNTU22.04 LTS"))) {
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
