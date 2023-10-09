# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6413.1");
  script_cve_id("CVE-2017-17122", "CVE-2017-8421", "CVE-2018-20671", "CVE-2018-6543", "CVE-2022-35205", "CVE-2022-47007", "CVE-2022-47008", "CVE-2022-47010", "CVE-2022-47011", "CVE-2022-48063");
  script_tag(name:"creation_date", value:"2023-10-05 04:08:26 +0000 (Thu, 05 Oct 2023)");
  script_version("2023-10-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-10-05 05:05:26 +0000 (Thu, 05 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-31 01:15:00 +0000 (Thu, 31 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-6413-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6413-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6413-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the USN-6413-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GNU binutils was not properly performing checks
when dealing with memory allocation operations, which could lead to
excessive memory consumption. An attacker could possibly use this issue
to cause a denial of service. This issue only affected Ubuntu 14.04 LTS.
(CVE-2017-17122, CVE-2017-8421)

It was discovered that GNU binutils was not properly performing bounds
checks when processing debug sections with objdump, which could lead to
an overflow. An attacker could possibly use this issue to cause a denial
of service or execute arbitrary code. This issue only affected Ubuntu
14.04 LTS. (CVE-2018-20671, CVE-2018-6543)

It was discovered that GNU binutils contained a reachable assertion, which
could lead to an intentional assertion failure when processing certain
crafted DWARF files. An attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 18.04 LTS.
(CVE-2022-35205)

It was discovered that GNU binutils incorrectly handled memory management
operations in several of its functions, which could lead to excessive
memory consumption due to memory leaks. An attacker could possibly use
these issues to cause a denial of service.
(CVE-2022-47007, CVE-2022-47008, CVE-2022-47010, CVE-2022-47011)

It was discovered that GNU binutils was not properly performing bounds
checks when dealing with memory allocation operations, which could lead
to excessive memory consumption. An attacker could possibly use this issue
to cause a denial of service. (CVE-2022-48063)");

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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.24-5ubuntu14.2+esm5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.24-5ubuntu14.2+esm5", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.26.1-1ubuntu1~16.04.8+esm9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.26.1-1ubuntu1~16.04.8+esm9", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.30-21ubuntu1~18.04.9+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.30-21ubuntu1~18.04.9+esm3", rls:"UBUNTU18.04 LTS"))) {
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
