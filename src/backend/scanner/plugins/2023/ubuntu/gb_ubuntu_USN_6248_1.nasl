# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6248.1");
  script_cve_id("CVE-2022-47929", "CVE-2023-21106", "CVE-2023-2640", "CVE-2023-31248", "CVE-2023-32629", "CVE-2023-3389", "CVE-2023-35001");
  script_tag(name:"creation_date", value:"2023-07-26 04:09:41 +0000 (Wed, 26 Jul 2023)");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-12 16:49:00 +0000 (Wed, 12 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6248-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6248-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6248-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.0' package(s) announced via the USN-6248-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the network queuing discipline implementation in the
Linux kernel contained a null pointer dereference in some situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2022-47929)

It was discovered that a race condition existed in Adreno GPU DRM driver in
the Linux kernel, leading to a double-free vulnerability. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2023-21106)

Stonejiajia, Shir Tamari and Sagi Tzadik discovered that the OverlayFS
implementation in the Ubuntu Linux kernel did not properly perform
permission checks in certain situations. A local attacker could possibly
use this to gain elevated privileges. (CVE-2023-2640)

Mingi Cho discovered that the netfilter subsystem in the Linux kernel did
not properly validate the status of a nft chain while performing a lookup
by id, leading to a use-after-free vulnerability. An attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-31248)

Shir Tamari and Sagi Tzadik discovered that the OverlayFS implementation in
the Ubuntu Linux kernel did not properly perform permission checks in
certain situations. A local attacker could possibly use this to gain
elevated privileges. (CVE-2023-32629)

Querijn Voet discovered that a race condition existed in the io_uring
subsystem in the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-3389)

Tanguy Dubroca discovered that the netfilter subsystem in the Linux kernel
did not properly handle certain pointer data type, leading to an out-of-
bounds write vulnerability. A privileged attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-35001)");

  script_tag(name:"affected", value:"'linux-oem-6.0' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.0.0-1020-oem", ver:"6.0.0-1020.20", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04b", ver:"6.0.0.1020.20", rls:"UBUNTU22.04 LTS"))) {
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
