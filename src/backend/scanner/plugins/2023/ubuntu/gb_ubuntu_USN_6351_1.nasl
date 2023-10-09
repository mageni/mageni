# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6351.1");
  script_cve_id("CVE-2022-48425", "CVE-2023-21255", "CVE-2023-2898", "CVE-2023-31084", "CVE-2023-3212", "CVE-2023-38426", "CVE-2023-38428", "CVE-2023-38429");
  script_tag(name:"creation_date", value:"2023-09-07 04:08:46 +0000 (Thu, 07 Sep 2023)");
  script_version("2023-09-07T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-07 05:05:21 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-27 16:11:00 +0000 (Thu, 27 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6351-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6351-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gke, linux-gkeop' package(s) announced via the USN-6351-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the NTFS file system implementation in the Linux
kernel did not properly validate MFT flags in certain situations. An
attacker could use this to construct a malicious NTFS image that, when
mounted and operated on, could cause a denial of service (system crash).
(CVE-2022-48425)

Zi Fan Tan discovered that the binder IPC implementation in the Linux
kernel contained a use-after-free vulnerability. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-21255)

It was discovered that a race condition existed in the f2fs file system in
the Linux kernel, leading to a null pointer dereference vulnerability. An
attacker could use this to construct a malicious f2fs image that, when
mounted and operated on, could cause a denial of service (system crash).
(CVE-2023-2898)

It was discovered that the DVB Core driver in the Linux kernel did not
properly handle locking events in certain situations. A local attacker
could use this to cause a denial of service (kernel deadlock).
(CVE-2023-31084)

Yang Lan discovered that the GFS2 file system implementation in the Linux
kernel could attempt to dereference a null pointer in some situations. An
attacker could use this to construct a malicious GFS2 image that, when
mounted and operated on, could cause a denial of service (system crash).
(CVE-2023-3212)

It was discovered that the KSMBD implementation in the Linux kernel did not
properly validate buffer sizes in certain operations, leading to an out-of-
bounds read vulnerability. A remote attacker could use this to cause a
denial of service (system crash) or possibly expose sensitive information.
(CVE-2023-38426, CVE-2023-38428)

It was discovered that the KSMBD implementation in the Linux kernel did not
properly calculate the size of certain buffers. A remote attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-38429)");

  script_tag(name:"affected", value:"'linux-gke, linux-gkeop' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1027-gkeop", ver:"5.15.0-1027.32", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1041-gke", ver:"5.15.0-1041.46", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.15.0.1041.40", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.15", ver:"5.15.0.1041.40", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.15.0.1027.26", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1027.26", rls:"UBUNTU22.04 LTS"))) {
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
