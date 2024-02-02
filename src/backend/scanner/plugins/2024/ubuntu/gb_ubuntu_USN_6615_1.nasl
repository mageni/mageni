# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6615.1");
  script_cve_id("CVE-2024-20960", "CVE-2024-20961", "CVE-2024-20962", "CVE-2024-20963", "CVE-2024-20964", "CVE-2024-20965", "CVE-2024-20966", "CVE-2024-20967", "CVE-2024-20969", "CVE-2024-20970", "CVE-2024-20971", "CVE-2024-20972", "CVE-2024-20973", "CVE-2024-20974", "CVE-2024-20976", "CVE-2024-20977", "CVE-2024-20978", "CVE-2024-20981", "CVE-2024-20982", "CVE-2024-20983", "CVE-2024-20984", "CVE-2024-20985");
  script_tag(name:"creation_date", value:"2024-01-31 04:08:56 +0000 (Wed, 31 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 22:15:45 +0000 (Tue, 16 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6615-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6615-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6615-1");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-36.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2024.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-8.0' package(s) announced via the USN-6615-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.36 in Ubuntu 20.04 LTS, Ubuntu 22.04 LTS,
and Ubuntu 23.10.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:

[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-8.0' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.36-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.36-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.36-0ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
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
