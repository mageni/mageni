# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6586.1");
  script_cve_id("CVE-2019-12211", "CVE-2019-12213", "CVE-2020-21427", "CVE-2020-21428", "CVE-2020-22524");
  script_tag(name:"creation_date", value:"2024-01-17 04:09:07 +0000 (Wed, 17 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-24 21:57:26 +0000 (Thu, 24 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6586-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6586-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6586-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeimage' package(s) announced via the USN-6586-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FreeImage incorrectly handled certain memory
operations. If a user were tricked into opening a crafted TIFF file, a
remote attacker could use this issue to cause a heap buffer overflow,
resulting in a denial of service attack. This issue only affected Ubuntu
16.04 LTS and Ubuntu 20.04 LTS. (CVE-2019-12211)

It was discovered that FreeImage incorrectly processed images under
certain circumstances. If a user were tricked into opening a crafted TIFF
file, a remote attacker could possibly use this issue to cause a stack
exhaustion condition, resulting in a denial of service attack. This issue
only affected Ubuntu 16.04 LTS and Ubuntu 20.04 LTS. (CVE-2019-12213)

It was discovered that FreeImage incorrectly processed certain images.
If a user or automated system were tricked into opening a specially
crafted image file, a remote attacker could possibly use this issue to
cause a denial of service or execute arbitrary code. (CVE-2020-21427,
CVE-2020-21428)

It was discovered that FreeImage incorrectly processed certain images.
If a user or automated system were tricked into opening a specially
crafted PFM file, an attacker could possibly use this issue to cause a
denial of service. (CVE-2020-22524)");

  script_tag(name:"affected", value:"'freeimage' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3", ver:"3.15.4-3ubuntu0.1+esm3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3", ver:"3.17.0+ds1-2ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimageplus3", ver:"3.17.0+ds1-2ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3", ver:"3.17.0+ds1-5+deb9u1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimageplus3", ver:"3.17.0+ds1-5+deb9u1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3", ver:"3.18.0+ds2-1ubuntu3.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimageplus3", ver:"3.18.0+ds2-1ubuntu3.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3", ver:"3.18.0+ds2-6ubuntu5.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimageplus3", ver:"3.18.0+ds2-6ubuntu5.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3", ver:"3.18.0+ds2-9ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimageplus3", ver:"3.18.0+ds2-9ubuntu0.1", rls:"UBUNTU23.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3", ver:"3.18.0+ds2-9.1ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimageplus3", ver:"3.18.0+ds2-9.1ubuntu0.1", rls:"UBUNTU23.10"))) {
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
