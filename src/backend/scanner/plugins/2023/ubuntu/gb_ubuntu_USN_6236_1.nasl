# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6236.1");
  script_cve_id("CVE-2021-26675", "CVE-2021-26676", "CVE-2021-33833", "CVE-2022-23096", "CVE-2022-23097", "CVE-2022-23098", "CVE-2022-32292", "CVE-2022-32293", "CVE-2023-28488");
  script_tag(name:"creation_date", value:"2023-07-20 04:09:37 +0000 (Thu, 20 Jul 2023)");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-09 16:51:00 +0000 (Tue, 09 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-6236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6236-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6236-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'connman' package(s) announced via the USN-6236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ConnMan could be made to write out of bounds. A
remote attacker could possibly use this issue to cause ConnMan to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2021-26675, CVE-2021-33833)

It was discovered that ConnMan could be made to leak sensitive information
via the gdhcp component. A remote attacker could possibly use this issue
to obtain information for further exploitation. This issue only affected
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS. (CVE-2021-26676)

It was discovered that ConnMan could be made to read out of bounds. A
remote attacker could possibly use this issue to case ConnMan to crash,
resulting in a denial of service. This issue only affected Ubuntu 16.04
LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS.
(CVE-2022-23096, CVE-2022-23097)

It was discovered that ConnMan could be made to run into an infinite loop.
A remote attacker could possibly use this issue to cause ConnMan to
consume resources and to stop operating, resulting in a denial of service.
This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04
LTS, and Ubuntu 22.04 LTS. (CVE-2022-23098)

It was discovered that ConnMan could be made to write out of bounds via
the gweb component. A remote attacker could possibly use this issue to
cause ConnMan to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS, Ubuntu
18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-32292)

It was discovered that ConnMan did not properly manage memory under
certain circumstances. A remote attacker could possibly use this issue to
cause ConnMan to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS, Ubuntu
18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-32293)

It was discovered that ConnMan could be made to write out of bounds via
the gdhcp component. A remote attacker could possibly use this issue to
cause ConnMan to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2023-28488)");

  script_tag(name:"affected", value:"'connman' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"connman", ver:"1.21-1.2+deb8u1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"connman", ver:"1.35-6ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"connman", ver:"1.36-2ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"connman", ver:"1.36-2.3ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"connman", ver:"1.41-2ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
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
