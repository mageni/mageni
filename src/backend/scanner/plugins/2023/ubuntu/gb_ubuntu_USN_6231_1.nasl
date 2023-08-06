# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6231.1");
  script_cve_id("CVE-2023-2124", "CVE-2023-3090", "CVE-2023-31084", "CVE-2023-3141", "CVE-2023-3212");
  script_tag(name:"creation_date", value:"2023-07-17 04:09:42 +0000 (Mon, 17 Jul 2023)");
  script_version("2023-07-17T05:05:06+0000");
  script_tag(name:"last_modification", value:"2023-07-17 05:05:06 +0000 (Mon, 17 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-06 16:09:00 +0000 (Thu, 06 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6231-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6231-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6231-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.1' package(s) announced via the USN-6231-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the XFS file system implementation in the Linux
kernel did not properly perform metadata validation when mounting certain
images. An attacker could use this to specially craft a file system image
that, when mounted, could cause a denial of service (system crash).
(CVE-2023-2124)

It was discovered that the IP-VLAN network driver for the Linux kernel did
not properly initialize memory in some situations, leading to an out-of-
bounds write vulnerability. An attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2023-3090)

It was discovered that the DVB Core driver in the Linux kernel did not
properly handle locking events in certain situations. A local attacker
could use this to cause a denial of service (kernel deadlock).
(CVE-2023-31084)

It was discovered that the Ricoh R5C592 MemoryStick card reader driver in
the Linux kernel contained a race condition during module unload, leading
to a use-after-free vulnerability. A local attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-3141)

Yang Lan discovered that the GFS2 file system implementation in the Linux
kernel could attempt to dereference a null pointer in some situations. An
attacker could use this to construct a malicious GFS2 image that, when
mounted and operated on, could cause a denial of service (system crash).
(CVE-2023-3212)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-1016-oem", ver:"6.1.0-1016.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04c", ver:"6.1.0.1016.16", rls:"UBUNTU22.04 LTS"))) {
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
