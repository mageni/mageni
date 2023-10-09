# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6386.2");
  script_cve_id("CVE-2023-20588", "CVE-2023-40283", "CVE-2023-4128", "CVE-2023-4569");
  script_tag(name:"creation_date", value:"2023-10-02 04:08:31 +0000 (Mon, 02 Oct 2023)");
  script_version("2023-10-02T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-10-02 05:05:22 +0000 (Mon, 02 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-16 20:32:00 +0000 (Wed, 16 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6386-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6386-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6386-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi' package(s) announced via the USN-6386-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jana Hofmann, Emanuele Vannacci, Cedric Fournet, Boris Kopf, and Oleksii
Oleksenko discovered that some AMD processors could leak stale data from
division operations in certain situations. A local attacker could possibly
use this to expose sensitive information. (CVE-2023-20588)

It was discovered that the bluetooth subsystem in the Linux kernel did not
properly handle L2CAP socket release, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-40283)

It was discovered that some network classifier implementations in the Linux
kernel contained use-after-free vulnerabilities. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-4128)

Lonial Con discovered that the netfilter subsystem in the Linux kernel
contained a memory leak when handling certain element flush operations. A
local attacker could use this to expose sensitive information (kernel
memory). (CVE-2023-4569)");

  script_tag(name:"affected", value:"'linux-raspi' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1038-raspi", ver:"5.15.0-1038.41", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.15.0.1038.36", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.15.0.1038.36", rls:"UBUNTU22.04 LTS"))) {
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
