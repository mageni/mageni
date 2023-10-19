# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6437.1");
  script_cve_id("CVE-2018-7998", "CVE-2019-6976", "CVE-2020-20739", "CVE-2021-27847", "CVE-2023-40032");
  script_tag(name:"creation_date", value:"2023-10-19 04:08:24 +0000 (Thu, 19 Oct 2023)");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 16:34:00 +0000 (Tue, 27 Mar 2018)");

  script_name("Ubuntu: Security Advisory (USN-6437-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6437-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6437-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vips' package(s) announced via the USN-6437-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ziqiang Gu discovered that VIPS could be made to dereference a NULL
pointer. If a user or automated system were tricked into processing
a specially crafted input image file, an attacker could possibly use
this issue to cause a denial of service. This issue only affected
Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-7998)

It was discovered that VIPS did not properly handle uninitialized memory
locations when processing corrupted input image data. An attacker could
possibly use this issue to generate output images that expose sensitive
information. This issue only affected Ubuntu 16.04 LTS
and Ubuntu 18.04 LTS. (CVE-2019-6976)

It was discovered that VIPS did not properly manage memory due to an
uninitialized variable. If a user or automated system were tricked into
processing a specially crafted output file, an attacker could possibly
use this issue to expose sensitive information.
This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2020-20739)

It was discovered that VIPS could be made to divide by zero in multiple
funcions. If a user or automated system were tricked into processing a
specially crafted image file, an attacker could possibly use this issue
to cause a denial of service. This issue only affected Ubuntu 16.04 LTS
and Ubuntu 18.04 LTS. (CVE-2021-27847)

It was discovered that VIPS did not properly handle certain input files
that contained malformed UTF-8 characters. If a user or automated system
were tricked into processing a specially crafted SVG image file, an
attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 22.04 LTS. (CVE-2023-40032)");

  script_tag(name:"affected", value:"'vips' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-vips-8.0", ver:"8.2.2-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvips-tools", ver:"8.2.2-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvips42", ver:"8.2.2-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-vipscc", ver:"8.2.2-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-vips-8.0", ver:"8.4.5-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvips-tools", ver:"8.4.5-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvips42", ver:"8.4.5-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-vipscc", ver:"8.4.5-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-vips-8.0", ver:"8.12.1-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvips-tools", ver:"8.12.1-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvips42", ver:"8.12.1-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
