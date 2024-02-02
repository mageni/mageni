# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6531.1");
  script_cve_id("CVE-2022-24834", "CVE-2022-35977", "CVE-2022-36021", "CVE-2023-25155", "CVE-2023-28856", "CVE-2023-45145");
  script_tag(name:"creation_date", value:"2023-12-06 04:08:43 +0000 (Wed, 06 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-25 18:56:46 +0000 (Tue, 25 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6531-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6531-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6531-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the USN-6531-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Seiya Nakata and Yudai Fujiwara discovered that Redis incorrectly handled
certain specially crafted Lua scripts. An attacker could possibly use this
issue to cause heap corruption and execute arbitrary code.
(CVE-2022-24834)

SeungHyun Lee discovered that Redis incorrectly handled specially crafted
commands. An attacker could possibly use this issue to trigger an integer
overflow, which might cause Redis to allocate impossible amounts of memory,
resulting in a denial of service via an application crash. (CVE-2022-35977)

Tom Levy discovered that Redis incorrectly handled crafted string matching
patterns. An attacker could possibly use this issue to cause Redis to hang,
resulting in a denial of service. (CVE-2022-36021)

Yupeng Yang discovered that Redis incorrectly handled specially crafted
commands. An attacker could possibly use this issue to trigger an integer
overflow, resulting in a denial of service via an application crash.
(CVE-2023-25155)

It was discovered that Redis incorrectly handled a specially crafted
command. An attacker could possibly use this issue to create an invalid
hash field, which could potentially cause Redis to crash on future access.
(CVE-2023-28856)

Alexander Aleksandrovic Klimov discovered that Redis incorrectly listened
to a Unix socket before setting proper permissions. A local attacker could
possibly use this issue to connect, bypassing intended permissions.
(CVE-2023-45145)");

  script_tag(name:"affected", value:"'redis' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"redis-server", ver:"2:2.8.4-2ubuntu0.2+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"2:2.8.4-2ubuntu0.2+esm3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"redis-server", ver:"2:3.0.6-1ubuntu0.4+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"2:3.0.6-1ubuntu0.4+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"redis-server", ver:"5:4.0.9-1ubuntu0.2+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"5:4.0.9-1ubuntu0.2+esm4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"redis-server", ver:"5:5.0.7-2ubuntu0.1+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"5:5.0.7-2ubuntu0.1+esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"redis-server", ver:"5:6.0.16-1ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"5:6.0.16-1ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
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
