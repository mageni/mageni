# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6625.2");
  script_cve_id("CVE-2023-34324", "CVE-2023-35827", "CVE-2023-45863", "CVE-2023-46343");
  script_tag(name:"creation_date", value:"2024-02-09 04:08:49 +0000 (Fri, 09 Feb 2024)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-26 17:11:20 +0000 (Mon, 26 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-6625-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6625-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6625-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp, linux-gcp-5.4' package(s) announced via the USN-6625-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marek Marczykowski-Gorecki discovered that the Xen event channel
infrastructure implementation in the Linux kernel contained a race
condition. An attacker in a guest VM could possibly use this to cause a
denial of service (paravirtualized device unavailability). (CVE-2023-34324)

Zheng Wang discovered a use-after-free in the Renesas Ethernet AVB driver
in the Linux kernel during device removal. A privileged attacker could use
this to cause a denial of service (system crash). (CVE-2023-35827)

It was discovered that a race condition existed in the Linux kernel when
performing operations with kernel objects, leading to an out-of-bounds
write. A local attacker could use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2023-45863)

Huang Si Cong discovered that the NFC Controller Interface (NCI) implementation in
the Linux kernel did not properly handle certain memory allocation failure
conditions, leading to a null pointer dereference vulnerability. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-46343)");

  script_tag(name:"affected", value:"'linux-gcp, linux-gcp-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1122-gcp", ver:"5.4.0-1122.131~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.4.0.1122.98", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1122-gcp", ver:"5.4.0-1122.131", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-20.04", ver:"5.4.0.1122.124", rls:"UBUNTU20.04 LTS"))) {
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
