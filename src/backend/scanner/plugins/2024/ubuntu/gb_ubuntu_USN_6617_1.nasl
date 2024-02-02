# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6617.1");
  script_cve_id("CVE-2020-21594", "CVE-2020-21595", "CVE-2020-21596", "CVE-2020-21597", "CVE-2020-21598", "CVE-2020-21599", "CVE-2020-21600", "CVE-2020-21601", "CVE-2020-21602", "CVE-2020-21603", "CVE-2020-21604", "CVE-2020-21605", "CVE-2020-21606", "CVE-2021-36408");
  script_tag(name:"creation_date", value:"2024-01-31 04:08:56 +0000 (Wed, 31 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-27 20:28:28 +0000 (Mon, 27 Sep 2021)");

  script_name("Ubuntu: Security Advisory (USN-6617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6617-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6617-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libde265' package(s) announced via the USN-6617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libde265 could be made to write out of bounds. If a
user or automated system were tricked into opening a specially crafted
file, an attacker could possibly use this issue to cause a denial of
service or execute arbitrary code. This issue only affected Ubuntu 16.04
LTS and Ubuntu 18.04 LTS. (CVE-2020-21594)

It was discovered that libde265 could be made to write out of bounds. If a
user or automated system were tricked into opening a specially crafted
file, an attacker could possibly use this issue to cause a denial of
service or execute arbitrary code. (CVE-2020-21595, CVE-2020-21596,
CVE-2020-21599, CVE-2020-21600, CVE-2020-21601, CVE-2020-21602,
CVE-2020-21603, CVE-2020-21604, CVE-2020-21605)

It was discovered that libde265 did not properly manage memory. If a user
or automated system were tricked into opening a specially crafted file, an
attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. This issue only affected Ubuntu 20.04 LTS.
(CVE-2020-21597, CVE-2020-21598, CVE-2020-21606, CVE-2021-36408)");

  script_tag(name:"affected", value:"'libde265' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.2-2ubuntu0.16.04.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.2-2ubuntu0.18.04.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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
