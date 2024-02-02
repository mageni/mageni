# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6590.1");
  script_cve_id("CVE-2018-1311", "CVE-2023-37536");
  script_tag(name:"creation_date", value:"2024-01-19 04:09:02 +0000 (Fri, 19 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-18 20:00:09 +0000 (Wed, 18 Oct 2023)");

  script_name("Ubuntu: Security Advisory (USN-6590-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6590-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6590-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-c' package(s) announced via the USN-6590-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Xerces-C++ was not properly handling memory
management operations when parsing XML data containing external DTDs,
which could trigger a use-after-free error. If a user or automated system
were tricked into processing a specially crafted XML document, an attacker
could possibly use this issue to cause a denial of service or execute
arbitrary code. This issue only affected Ubuntu 22.04 LTS. (CVE-2018-1311)

It was discovered that Xerces-C++ was not properly performing bounds
checks when processing XML Schema Definition files, which could lead to an
out-of-bounds access via an HTTP request. If a user or automated system
were tricked into processing a specially crafted XSD file, a remote
attacker could possibly use this issue to cause a denial of service.
(CVE-2023-37536)");

  script_tag(name:"affected", value:"'xerces-c' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-samples", ver:"3.1.1-5.1+deb8u4ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c3.1", ver:"3.1.1-5.1+deb8u4ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-samples", ver:"3.1.3+debian-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c3.1", ver:"3.1.3+debian-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-samples", ver:"3.2.0+debian-2ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c3.2", ver:"3.2.0+debian-2ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-samples", ver:"3.2.2+debian-1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c3.2", ver:"3.2.2+debian-1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-samples", ver:"3.2.3+debian-3ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxerces-c3.2", ver:"3.2.3+debian-3ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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
