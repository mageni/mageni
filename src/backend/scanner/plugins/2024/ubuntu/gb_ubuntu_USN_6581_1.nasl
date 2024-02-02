# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6581.1");
  script_cve_id("CVE-2022-44840", "CVE-2022-45703", "CVE-2022-47007", "CVE-2022-47008", "CVE-2022-47010", "CVE-2022-47011");
  script_tag(name:"creation_date", value:"2024-01-16 09:59:41 +0000 (Tue, 16 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-26 02:14:12 +0000 (Sat, 26 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6581-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6581-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6581-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the USN-6581-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GNU binutils was not properly performing bounds
checks in several functions, which could lead to a buffer overflow. An
attacker could possibly use this issue to cause a denial of service,
expose sensitive information or execute arbitrary code.
(CVE-2022-44840, CVE-2022-45703)

It was discovered that GNU binutils incorrectly handled memory management
operations in several of its functions, which could lead to excessive
memory consumption due to memory leaks. An attacker could possibly use
these issues to cause a denial of service.
(CVE-2022-47007, CVE-2022-47008, CVE-2022-47010, CVE-2022-47011)");

  script_tag(name:"affected", value:"'binutils' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.34-6ubuntu1.8", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.34-6ubuntu1.8", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.38-4ubuntu2.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.38-4ubuntu2.5", rls:"UBUNTU22.04 LTS"))) {
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
