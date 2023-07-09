# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6181.1");
  script_cve_id("CVE-2021-33621", "CVE-2023-28755", "CVE-2023-28756");
  script_tag(name:"creation_date", value:"2023-06-22 04:09:38 +0000 (Thu, 22 Jun 2023)");
  script_version("2023-06-22T10:34:14+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:14 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-22 21:04:00 +0000 (Tue, 22 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-6181-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.10|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6181-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6181-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby3.1' package(s) announced via the USN-6181-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hiroshi Tokumaru discovered that Ruby did not properly handle certain
user input for applications the generate HTTP responses using cgi gem.
An attacker could possibly use this issue to maliciously modify the
response a user would receive from a vulnerable application. This issue
only affected Ubuntu 22.10. (CVE-2021-33621)

It was discovered that Ruby incorrectly handled certain regular expressions.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2023-28755, CVE-2023-28756)");

  script_tag(name:"affected", value:"'ruby3.1' package(s) on Ubuntu 22.10, Ubuntu 23.04.");

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

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby3.1", ver:"3.1.2-2ubuntu0.22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby3.1", ver:"3.1.2-2ubuntu0.22.10.1", rls:"UBUNTU22.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby3.1", ver:"3.1.2-6ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby3.1", ver:"3.1.2-6ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
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
