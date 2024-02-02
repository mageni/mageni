# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6557.1");
  script_cve_id("CVE-2022-1725", "CVE-2022-1771", "CVE-2022-1886", "CVE-2022-1897", "CVE-2022-2000", "CVE-2022-2042", "CVE-2023-46246", "CVE-2023-48231", "CVE-2023-48232", "CVE-2023-48233", "CVE-2023-48234", "CVE-2023-48235", "CVE-2023-48236", "CVE-2023-48237", "CVE-2023-48706");
  script_tag(name:"creation_date", value:"2023-12-15 04:08:53 +0000 (Fri, 15 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-08 18:19:47 +0000 (Tue, 08 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-6557-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6557-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6557-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the USN-6557-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Vim could be made to dereference invalid memory. An
attacker could possibly use this issue to cause a denial of service. This
issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04
LTS. (CVE-2022-1725)

It was discovered that Vim could be made to recurse infinitely. An
attacker could possibly use this issue to cause a denial of service. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS,
Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-1771)

It was discovered that Vim could be made to write out of bounds with a put
command. An attacker could possibly use this issue to cause a denial of
service or execute arbitrary code. This issue only affected Ubuntu 22.04
LTS. (CVE-2022-1886)

It was discovered that Vim could be made to write out of bounds. An
attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS, Ubuntu
18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-1897,
CVE-2022-2000)

It was discovered that Vim did not properly manage memory in the spell
command. An attacker could possibly use this issue to cause a denial of
service or execute arbitrary code. This issue only affected Ubuntu 22.04
LTS. (CVE-2022-2042)

It was discovered that Vim did not properly manage memory. An attacker
could possibly use this issue to cause a denial of service or execute
arbitrary code. (CVE-2023-46246, CVE-2023-48231)

It was discovered that Vim could be made to divide by zero. An attacker
could possibly use this issue to cause a denial of service. This issue
only affected Ubuntu 23.04 and Ubuntu 23.10. (CVE-2023-48232)

It was discovered that Vim contained multiple arithmetic overflows. An
attacker could possibly use these issues to cause a denial of service.
(CVE-2023-48233, CVE-2023-48234, CVE-2023-48235, CVE-2023-48236,
CVE-2023-48237)

It was discovered that Vim did not properly manage memory in the
substitute command. An attacker could possibly use this issue to cause a
denial of service or execute arbitrary code. This issue only affected
Ubuntu 22.04 LTS, Ubuntu 23.04, and Ubuntu 23.10. (CVE-2023-48706)");

  script_tag(name:"affected", value:"'vim' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:7.4.052-1ubuntu3.1+esm15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:7.4.052-1ubuntu3.1+esm15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:7.4.052-1ubuntu3.1+esm15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:7.4.052-1ubuntu3.1+esm15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:7.4.052-1ubuntu3.1+esm15", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:7.4.1689-3ubuntu1.5+esm22", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:7.4.1689-3ubuntu1.5+esm22", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:7.4.1689-3ubuntu1.5+esm22", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:7.4.1689-3ubuntu1.5+esm22", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:7.4.1689-3ubuntu1.5+esm22", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:7.4.1689-3ubuntu1.5+esm22", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.0.1453-1ubuntu1.13+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.0.1453-1ubuntu1.13+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.0.1453-1ubuntu1.13+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.0.1453-1ubuntu1.13+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.0.1453-1ubuntu1.13+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.0.1453-1ubuntu1.13+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.0.1453-1ubuntu1.13+esm7", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.1.2269-1ubuntu5.21", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.1.2269-1ubuntu5.21", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.1.2269-1ubuntu5.21", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.1.2269-1ubuntu5.21", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.1.2269-1ubuntu5.21", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.1.2269-1ubuntu5.21", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.1.2269-1ubuntu5.21", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.2.3995-1ubuntu2.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.2.3995-1ubuntu2.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.2.3995-1ubuntu2.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.2.3995-1ubuntu2.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.2.3995-1ubuntu2.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.2.3995-1ubuntu2.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.2.3995-1ubuntu2.15", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:9.0.1000-4ubuntu3.3", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:9.0.1000-4ubuntu3.3", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:9.0.1000-4ubuntu3.3", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:9.0.1000-4ubuntu3.3", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:9.0.1000-4ubuntu3.3", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:9.0.1000-4ubuntu3.3", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:9.0.1672-1ubuntu2.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:9.0.1672-1ubuntu2.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:9.0.1672-1ubuntu2.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:9.0.1672-1ubuntu2.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:9.0.1672-1ubuntu2.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:9.0.1672-1ubuntu2.2", rls:"UBUNTU23.10"))) {
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
