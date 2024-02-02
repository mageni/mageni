# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6529.1");
  script_cve_id("CVE-2021-38562", "CVE-2022-25802", "CVE-2023-41259", "CVE-2023-41260");
  script_tag(name:"creation_date", value:"2023-12-05 04:09:15 +0000 (Tue, 05 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 17:17:24 +0000 (Mon, 13 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6529-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6529-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6529-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'request-tracker4' package(s) announced via the USN-6529-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Request Tracker incorrectly handled certain inputs. If
a user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to obtain
sensitive information. (CVE-2021-38562, CVE-2022-25802, CVE-2023-41259,
CVE-2023-41260)");

  script_tag(name:"affected", value:"'request-tracker4' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.4.2-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.4.2-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.4.2-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.4.2-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.4.2-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.4.2-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.4.2-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.4.2-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.4.3-2+deb10u3build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.4.3-2+deb10u3build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.4.3-2+deb10u3build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.4.3-2+deb10u3build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.4.3-2+deb10u3build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.4.3-2+deb10u3build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.4.3-2+deb10u3build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.4.3-2+deb10u3build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.4.4+dfsg-2ubuntu1.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.4.4+dfsg-2ubuntu1.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.4.4+dfsg-2ubuntu1.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.4.4+dfsg-2ubuntu1.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.4.4+dfsg-2ubuntu1.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.4.4+dfsg-2ubuntu1.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.4.4+dfsg-2ubuntu1.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.4.4+dfsg-2ubuntu1.22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.4.4+dfsg-2ubuntu1.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.4.4+dfsg-2ubuntu1.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.4.4+dfsg-2ubuntu1.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.4.4+dfsg-2ubuntu1.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.4.4+dfsg-2ubuntu1.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.4.4+dfsg-2ubuntu1.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.4.4+dfsg-2ubuntu1.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.4.4+dfsg-2ubuntu1.23.04.1", rls:"UBUNTU23.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.4.4+dfsg-2ubuntu1.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.4.4+dfsg-2ubuntu1.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.4.4+dfsg-2ubuntu1.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.4.4+dfsg-2ubuntu1.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.4.4+dfsg-2ubuntu1.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.4.4+dfsg-2ubuntu1.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.4.4+dfsg-2ubuntu1.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.4.4+dfsg-2ubuntu1.23.10.1", rls:"UBUNTU23.10"))) {
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
