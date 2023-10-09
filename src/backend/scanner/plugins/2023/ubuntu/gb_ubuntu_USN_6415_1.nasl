# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6415.1");
  script_cve_id("CVE-2023-20569", "CVE-2023-25775", "CVE-2023-37453", "CVE-2023-3772", "CVE-2023-3773", "CVE-2023-42753", "CVE-2023-4622", "CVE-2023-4623");
  script_tag(name:"creation_date", value:"2023-10-05 04:08:26 +0000 (Thu, 05 Oct 2023)");
  script_version("2023-10-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-10-05 05:05:26 +0000 (Thu, 05 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 20:10:00 +0000 (Thu, 17 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6415-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6415-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6415-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.1' package(s) announced via the USN-6415-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Trujillo, Johannes Wikner, and Kaveh Razavi discovered that some AMD
processors utilising speculative execution and branch prediction may allow
unauthorised memory reads via a speculative side-channel attack. A local
attacker could use this to expose sensitive information, including kernel
memory. (CVE-2023-20569)

Ivan D Barrera, Christopher Bednarz, Mustafa Ismail, and Shiraz Saleem
discovered that the InfiniBand RDMA driver in the Linux kernel did not
properly check for zero-length STAG or MR registration. A remote attacker
could possibly use this to execute arbitrary code. (CVE-2023-25775)

It was discovered that the USB subsystem in the Linux kernel contained a
race condition while handling device descriptors in certain situations,
leading to a out-of-bounds read vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2023-37453)

Lin Ma discovered that the Netlink Transformation (XFRM) subsystem in the
Linux kernel contained a null pointer dereference vulnerability in some
situations. A local privileged attacker could use this to cause a denial of
service (system crash). (CVE-2023-3772)

Lin Ma discovered that the Netlink Transformation (XFRM) subsystem in the
Linux kernel did not properly initialize a policy data structure, leading
to an out-of-bounds vulnerability. A local privileged attacker could use
this to cause a denial of service (system crash) or possibly expose
sensitive information (kernel memory). (CVE-2023-3773)

Kyle Zeng discovered that the netfiler subsystem in the Linux kernel did
not properly calculate array offsets, leading to a out-of-bounds write
vulnerability. A local user could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-42753)

Bing-Jhong Billy Jheng discovered that the Unix domain socket
implementation in the Linux kernel contained a race condition in certain
situations, leading to a use-after-free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-4622)

Budimir Markovic discovered that the qdisc implementation in the Linux
kernel did not properly validate inner classes, leading to a use-after-free
vulnerability. A local user could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-4623)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-1023-oem", ver:"6.1.0-1023.23", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04a", ver:"6.1.0.1023.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04b", ver:"6.1.0.1023.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04c", ver:"6.1.0.1023.24", rls:"UBUNTU22.04 LTS"))) {
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
