# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6219.1");
  script_cve_id("CVE-2023-28755", "CVE-2023-36617");
  script_tag(name:"creation_date", value:"2023-07-13 04:09:42 +0000 (Thu, 13 Jul 2023)");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-06 18:34:00 +0000 (Thu, 06 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6219-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6219-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6219-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.3, ruby2.5, ruby2.7, ruby3.0, ruby3.1' package(s) announced via the USN-6219-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ruby incorrectly handled certain regular expressions.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 20.10 and Ubuntu 20.04 LTS.
(CVE-2023-28755)

It was discovered that Ruby incorrectly handled certain regular expressions.
An attacker could possibly use this issue to cause a denial of service.
This issue exists because of an incomplete fix for CVE-2023-28755.
(CVE-2023-36617)");

  script_tag(name:"affected", value:"'ruby2.3, ruby2.5, ruby2.7, ruby3.0, ruby3.1' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10, Ubuntu 23.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.1-2~ubuntu16.04.16+esm8", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.1-2~ubuntu16.04.16+esm8", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.5", ver:"2.5.1-1ubuntu1.16+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5", ver:"2.5.1-1ubuntu1.16+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.7", ver:"2.7.0-5ubuntu1.12", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.7", ver:"2.7.0-5ubuntu1.12", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby3.0", ver:"3.0.2-7ubuntu2.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby3.0", ver:"3.0.2-7ubuntu2.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby3.0", ver:"3.0.4-7ubuntu0.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby3.0", ver:"3.0.4-7ubuntu0.2", rls:"UBUNTU22.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby3.1", ver:"3.1.2-6ubuntu0.23.04.2", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby3.1", ver:"3.1.2-6ubuntu0.23.04.2", rls:"UBUNTU23.04"))) {
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
