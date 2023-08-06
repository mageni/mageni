# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6270.1");
  script_cve_id("CVE-2022-2182", "CVE-2022-2208", "CVE-2022-2210", "CVE-2022-2231", "CVE-2022-2257", "CVE-2022-2264", "CVE-2022-2284", "CVE-2022-2285", "CVE-2022-2286", "CVE-2022-2287", "CVE-2022-2289");
  script_tag(name:"creation_date", value:"2023-08-04 04:08:45 +0000 (Fri, 04 Aug 2023)");
  script_version("2023-08-04T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-12 15:34:00 +0000 (Tue, 12 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-6270-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6270-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6270-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the USN-6270-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Vim incorrectly handled memory when opening certain
files. If an attacker could trick a user into opening a specially crafted
file, it could cause Vim to crash, or possibly execute arbitrary code. This
issue only affected Ubuntu 22.04 LTS. (CVE-2022-2182)

It was discovered that Vim incorrectly handled memory when deleting buffers
in diff mode. An attacker could possibly use this issue to cause a denial
of service. This issue only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2022-2208)

It was discovered that Vim incorrectly handled memory access. An attacker
could possibly use this issue to cause the corruption of sensitive
information, a crash, or arbitrary code execution. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2022-2210)

It was discovered that Vim incorrectly handled memory when using nested
:source. An attacker could possibly use this issue to cause a denial of
service. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-2231)

It was discovered that Vim did not properly perform bounds checks when
processing a menu item with the only modifier. An attacker could possibly
use this issue to cause a denial of service. (CVE-2022-2257)

It was discovered that Vim incorrectly handled memory when opening certain
files. If an attacker could trick a user into opening a specially crafted
file, it could cause Vim to crash, or possibly execute arbitrary code.
(CVE-2022-2264, CVE-2022-2284, CVE-2022-2289)

It was discovered that Vim did not properly perform bounds checks when
going over the end of the typahead. An attacker could possibly use this
issue to cause a denial of service. (CVE-2022-2285)

It was discovered that Vim did not properly perform bounds checks when
reading the provided string. An attacker could possibly use this issue to
cause a denial of service. (CVE-2022-2286)

It was discovered that Vim incorrectly handled memory when adding words
with a control character to the internal spell word list. An attacker could
possibly use this issue to cause a denial of service. (CVE-2022-2287)");

  script_tag(name:"affected", value:"'vim' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:7.4.052-1ubuntu3.1+esm11", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:7.4.052-1ubuntu3.1+esm11", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:7.4.052-1ubuntu3.1+esm11", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:7.4.052-1ubuntu3.1+esm11", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:7.4.052-1ubuntu3.1+esm11", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:7.4.1689-3ubuntu1.5+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:7.4.1689-3ubuntu1.5+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:7.4.1689-3ubuntu1.5+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:7.4.1689-3ubuntu1.5+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:7.4.1689-3ubuntu1.5+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:7.4.1689-3ubuntu1.5+esm19", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.0.1453-1ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.0.1453-1ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.0.1453-1ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.0.1453-1ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.0.1453-1ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.0.1453-1ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.0.1453-1ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.1.2269-1ubuntu5.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.1.2269-1ubuntu5.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.1.2269-1ubuntu5.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.1.2269-1ubuntu5.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.1.2269-1ubuntu5.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.1.2269-1ubuntu5.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.1.2269-1ubuntu5.16", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.2.3995-1ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.2.3995-1ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.2.3995-1ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.2.3995-1ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.2.3995-1ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.2.3995-1ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.2.3995-1ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
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
