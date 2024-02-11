# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6627.1");
  script_cve_id("CVE-2021-35452", "CVE-2021-36408", "CVE-2021-36409", "CVE-2021-36410", "CVE-2021-36411", "CVE-2022-1253", "CVE-2022-43235", "CVE-2022-43236", "CVE-2022-43237", "CVE-2022-43238", "CVE-2022-43239", "CVE-2022-43240", "CVE-2022-43241", "CVE-2022-43242", "CVE-2022-43243", "CVE-2022-43248", "CVE-2022-43252", "CVE-2022-43253");
  script_tag(name:"creation_date", value:"2024-02-09 04:08:49 +0000 (Fri, 09 Feb 2024)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-14 17:52:13 +0000 (Thu, 14 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-6627-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6627-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6627-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libde265' package(s) announced via the USN-6627-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libde265 could be made to read out of bounds. If a
user or automated system were tricked into opening a specially crafted
file, an attacker could possibly use this issue to cause a denial of
service. (CVE-2021-35452, CVE-2021-36411, CVE-2022-43238, CVE-2022-43241,
CVE-2022-43242)

It was discovered that libde265 did not properly manage memory. If a user
or automated system were tricked into opening a specially crafted file, an
attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. This issue only affected Ubuntu 22.04 LTS.
(CVE-2021-36408)

It was discovered that libde265 contained a logical error. If a user
or automated system were tricked into opening a specially crafted file, an
attacker could possibly use this issue to cause a denial of service.
(CVE-2021-36409)

It was discovered that libde265 could be made to write out of bounds. If a
user or automated system were tricked into opening a specially crafted
file, an attacker could possibly use this issue to cause a denial of
service or execute arbitrary code. (CVE-2021-36410, CVE-2022-43235,
CVE-2022-43236, CVE-2022-43237, CVE-2022-43239, CVE-2022-43240,
CVE-2022-43243, CVE-2022-43248, CVE-2022-43252, CVE-2022-43253)

It was discovered that libde265 could be made to write out of bounds. If a
user or automated system were tricked into opening a specially crafted
file, an attacker could possibly use this issue to cause a denial of
service or execute arbitrary code. This issue only affected Ubuntu 22.04
LTS. (CVE-2022-1253)");

  script_tag(name:"affected", value:"'libde265' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.2-2ubuntu0.16.04.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.2-2ubuntu0.18.04.1~esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.4-1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.8-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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
