# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6287.1");
  script_cve_id("CVE-2021-4235", "CVE-2022-3064");
  script_tag(name:"creation_date", value:"2023-08-14 09:48:54 +0000 (Mon, 14 Aug 2023)");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-06 13:51:00 +0000 (Fri, 06 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-6287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6287-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6287-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-yaml.v2' package(s) announced via the USN-6287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Simon Ferquel discovered that the Go yaml package incorrectly handled
certain YAML documents. If a user or an automated system were tricked
into opening a specially crafted input file, a remote attacker could
possibly use this issue to cause the system to crash, resulting in
a denial of service. (CVE-2021-4235)

It was discovered that the Go yaml package incorrectly handled
certain large YAML documents. If a user or an automated system were tricked
into opening a specially crafted input file, a remote attacker could
possibly use this issue to cause the system to crash, resulting in
a denial of service. (CVE-2022-3064)");

  script_tag(name:"affected", value:"'golang-yaml.v2' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"golang-yaml.v2-dev", ver:"0.0+git20160301.0.a83829b-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-gopkg-yaml.v2-dev", ver:"0.0+git20170407.0.cd8b52f-1ubuntu2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-yaml.v2-dev", ver:"0.0+git20170407.0.cd8b52f-1ubuntu2+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-gopkg-yaml.v2-dev", ver:"2.2.2-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-yaml.v2-dev", ver:"2.2.2-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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
