# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6454.3");
  script_cve_id("CVE-2023-42756", "CVE-2023-4881", "CVE-2023-4921", "CVE-2023-5197");
  script_tag(name:"creation_date", value:"2023-11-01 13:52:44 +0000 (Wed, 01 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 19:38:11 +0000 (Thu, 14 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6454-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU23\.10");

  script_xref(name:"Advisory-ID", value:"USN-6454-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6454-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-laptop' package(s) announced via the USN-6454-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kyle Zeng discovered that the netfilter subsystem in the Linux kernel
contained a race condition in IP set operations in certain situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-42756)

Alex Birnberg discovered that the netfilter subsystem in the Linux kernel
did not properly validate register length, leading to an out-of- bounds
write vulnerability. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2023-4881)

It was discovered that the Quick Fair Queueing scheduler implementation in
the Linux kernel did not properly handle network packets in certain
conditions, leading to a use after free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-4921)

Kevin Rich discovered that the netfilter subsystem in the Linux kernel did
not properly handle removal of rules from chain bindings in certain
circumstances, leading to a use-after-free vulnerability. A local attacker
could possibly use this to cause a denial of service (system crash) or
execute arbitrary code. (CVE-2023-5197)");

  script_tag(name:"affected", value:"'linux-laptop' package(s) on Ubuntu 23.10.");

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

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1005-laptop", ver:"6.5.0-1005.8", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-laptop-23.10", ver:"6.5.0.1005.8", rls:"UBUNTU23.10"))) {
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
