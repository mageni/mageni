# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6381.1");
  script_cve_id("CVE-2020-19724", "CVE-2020-19726", "CVE-2020-21490", "CVE-2020-35342", "CVE-2021-46174", "CVE-2022-44840", "CVE-2022-45703", "CVE-2022-47695");
  script_tag(name:"creation_date", value:"2023-09-19 04:08:23 +0000 (Tue, 19 Sep 2023)");
  script_version("2023-09-19T05:06:02+0000");
  script_tag(name:"last_modification", value:"2023-09-19 05:06:02 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-25 02:46:00 +0000 (Fri, 25 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6381-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6381-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6381-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the USN-6381-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a memory leak existed in certain GNU binutils
modules. An attacker could possibly use this issue to cause a denial of
service (memory exhaustion). (CVE-2020-19724, CVE-2020-21490)

It was discovered that GNU binutils was not properly performing bounds
checks in several functions, which could lead to a buffer overflow. An
attacker could possibly use this issue to cause a denial of service,
expose sensitive information or execute arbitrary code.
(CVE-2020-19726, CVE-2021-46174, CVE-2022-45703)

It was discovered that GNU binutils was not properly initializing heap
memory when processing certain print instructions. An attacker could
possibly use this issue to expose sensitive information. (CVE-2020-35342)

It was discovered that GNU binutils was not properly handling the logic
behind certain memory management related operations, which could lead to a
buffer overflow. An attacker could possibly use this issue to cause a
denial of service or execute arbitrary code. (CVE-2022-44840)

It was discovered that GNU binutils was not properly handling the logic
behind certain memory management related operations, which could lead to
an invalid memory access. An attacker could possibly use this issue to
cause a denial of service. (CVE-2022-47695)");

  script_tag(name:"affected", value:"'binutils' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.24-5ubuntu14.2+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.24-5ubuntu14.2+esm3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.26.1-1ubuntu1~16.04.8+esm7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.26.1-1ubuntu1~16.04.8+esm7", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.30-21ubuntu1~18.04.9+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.30-21ubuntu1~18.04.9+esm1", rls:"UBUNTU18.04 LTS"))) {
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
