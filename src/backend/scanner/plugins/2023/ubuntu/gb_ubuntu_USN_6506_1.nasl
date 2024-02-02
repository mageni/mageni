# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6506.1");
  script_cve_id("CVE-2023-31122", "CVE-2023-43622", "CVE-2023-45802");
  script_tag(name:"creation_date", value:"2023-11-23 04:08:34 +0000 (Thu, 23 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 18:11:02 +0000 (Wed, 01 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6506-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6506-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6506-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-6506-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Shoon discovered that the Apache HTTP Server mod_macro module
incorrectly handled certain memory operations. A remote attacker could
possibly use this issue to cause the server to crash, resulting in a denial
of service. (CVE-2023-31122)

Prof. Sven Dietrich, Isa Jafarov, Prof. Heejo Lee, and Choongin Lee
discovered that the Apache HTTP Server incorrectly handled certain HTTP/2
connections. A remote attacker could possibly use this issue to cause the
server to consume resources, leading to a denial of service. This issue
only affected Ubuntu 23.04, and Ubuntu 23.10. (CVE-2023-43622)

Will Dormann and David Warren discovered that the Apache HTTP Server
incorrectly handled memory when handling HTTP/2 connections. A remote
attacker could possibly use this issue to cause the server to consume
resources, leading to a denial of service. (CVE-2023-45802)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.41-4ubuntu3.15", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.52-1ubuntu4.7", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.55-1ubuntu2.1", rls:"UBUNTU23.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.57-2ubuntu2.1", rls:"UBUNTU23.10"))) {
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
