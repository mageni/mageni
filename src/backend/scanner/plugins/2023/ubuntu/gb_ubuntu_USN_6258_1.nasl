# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6258.1");
  script_cve_id("CVE-2023-29932", "CVE-2023-29933", "CVE-2023-29934", "CVE-2023-29939");
  script_tag(name:"creation_date", value:"2023-07-28 04:09:30 +0000 (Fri, 28 Jul 2023)");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-11 18:19:00 +0000 (Thu, 11 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-6258-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6258-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6258-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'llvm-toolchain-13, llvm-toolchain-14, llvm-toolchain-15' package(s) announced via the USN-6258-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LLVM Toolchain did not properly manage memory under
certain circumstances. If a user were tricked into opening a specially
crafted MLIR file, an attacker could possibly use this issue to cause LLVM
Toolchain to crash, resulting in a denial of service. (CVE-2023-29932,
CVE-2023-29934, CVE-2023-29939)

It was discovered that LLVM Toolchain did not properly manage memory under
certain circumstances. If a user were tricked into opening a specially
crafted MLIR file, an attacker could possibly use this issue to cause LLVM
Toolchain to crash, resulting in a denial of service. This issue only
affected llvm-toolchain-15. (CVE-2023-29933)");

  script_tag(name:"affected", value:"'llvm-toolchain-13, llvm-toolchain-14, llvm-toolchain-15' package(s) on Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"llvm-13", ver:"1:13.0.1-2ubuntu2.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-13-tools", ver:"1:13.0.1-2ubuntu2.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-14", ver:"1:14.0.0-1ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-14-tools", ver:"1:14.0.0-1ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-15", ver:"1:15.0.7-0ubuntu0.22.04.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-15-tools", ver:"1:15.0.7-0ubuntu0.22.04.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mlir-13-tools", ver:"1:13.0.1-2ubuntu2.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mlir-14-tools", ver:"1:14.0.0-1ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mlir-15-tools", ver:"1:15.0.7-0ubuntu0.22.04.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"llvm-13", ver:"1:13.0.1-11ubuntu14.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-13-tools", ver:"1:13.0.1-11ubuntu14.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-14", ver:"1:14.0.6-12ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-14-tools", ver:"1:14.0.6-12ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-15", ver:"1:15.0.7-3ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"llvm-15-tools", ver:"1:15.0.7-3ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mlir-13-tools", ver:"1:13.0.1-11ubuntu14.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mlir-14-tools", ver:"1:14.0.6-12ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mlir-15-tools", ver:"1:15.0.7-3ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
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
