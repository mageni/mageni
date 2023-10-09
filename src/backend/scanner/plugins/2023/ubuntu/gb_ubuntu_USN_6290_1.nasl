# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6290.1");
  script_cve_id("CVE-2022-48281", "CVE-2023-25433", "CVE-2023-26965", "CVE-2023-26966", "CVE-2023-2731", "CVE-2023-2908", "CVE-2023-3316", "CVE-2023-3618", "CVE-2023-38288", "CVE-2023-38289");
  script_tag(name:"creation_date", value:"2023-08-16 10:50:22 +0000 (Wed, 16 Aug 2023)");
  script_version("2023-08-17T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-08-17 05:05:20 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-20 17:16:00 +0000 (Thu, 20 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6290-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6290-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6290-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the USN-6290-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LibTIFF could be made to write out of bounds when
processing certain malformed image files with the tiffcrop utility. If a
user were tricked into opening a specially crafted image file, an attacker
could possibly use this issue to cause tiffcrop to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS.
(CVE-2022-48281)

It was discovered that LibTIFF incorrectly handled certain image files. If
a user were tricked into opening a specially crafted image file, an
attacker could possibly use this issue to cause a denial of service. This
issue only affected Ubuntu 23.04. (CVE-2023-2731)

It was discovered that LibTIFF incorrectly handled certain image files
with the tiffcp utility. If a user were tricked into opening a specially
crafted image file, an attacker could possibly use this issue to cause
tiffcp to crash, resulting in a denial of service. (CVE-2023-2908)

It was discovered that LibTIFF incorrectly handled certain file paths. If
a user were tricked into specifying certain output paths, an attacker
could possibly use this issue to cause a denial of service. This issue
only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-3316)

It was discovered that LibTIFF could be made to write out of bounds when
processing certain malformed image files. If a user were tricked into
opening a specially crafted image file, an attacker could possibly use
this issue to cause a denial of service, or possibly execute arbitrary
code. (CVE-2023-3618)

It was discovered that LibTIFF could be made to write out of bounds when
processing certain malformed image files. If a user were tricked into
opening a specially crafted image file, an attacker could possibly use
this issue to cause a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and
Ubuntu 23.04. (CVE-2023-25433, CVE-2023-26966)

It was discovered that LibTIFF did not properly managed memory when
processing certain malformed image files with the tiffcrop utility. If a
user were tricked into opening a specially crafted image file, an attacker
could possibly use this issue to cause tiffcrop to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 23.04.
(CVE-2023-26965)

It was discovered that LibTIFF contained an arithmetic overflow. If a user
were tricked into opening a specially crafted image file, an attacker
could possibly use this issue to cause a denial of service.
(CVE-2023-38288, CVE-2023-38289)");

  script_tag(name:"affected", value:"'tiff' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.3-7ubuntu0.11+esm9", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.3-7ubuntu0.11+esm9", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.6-1ubuntu0.8+esm12", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.6-1ubuntu0.8+esm12", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.9-5ubuntu0.10+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.9-5ubuntu0.10+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.1.0+git191117-2ubuntu0.20.04.9", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.1.0+git191117-2ubuntu0.20.04.9", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.3.0-6ubuntu0.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.3.0-6ubuntu0.5", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.5.0-5ubuntu1.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff6", ver:"4.5.0-5ubuntu1.1", rls:"UBUNTU23.04"))) {
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
