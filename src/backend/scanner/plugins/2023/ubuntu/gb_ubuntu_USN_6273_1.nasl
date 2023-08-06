# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6273.1");
  script_cve_id("CVE-2022-27337", "CVE-2023-34872");
  script_tag(name:"creation_date", value:"2023-08-04 04:08:45 +0000 (Fri, 04 Aug 2023)");
  script_version("2023-08-04T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-13 04:05:00 +0000 (Fri, 13 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-6273-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6273-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6273-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the USN-6273-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jieyong Ma discovered that poppler incorrectly handled certain malformed
PDF files. A remote attacker could possibly use this issue to cause poppler
to crash, resulting in a denial of service. This issue only affected Ubuntu
20.04 LTS and Ubuntu 22.04 LTS. (CVE-2022-27337)

It was discovered that poppler incorrectly handled certain malformed PDF
files. A remote attacker could possibly use this issue to cause poppler to
crash, resulting in a denial of service. This issue only affected Ubuntu
22.04 LTS and Ubuntu 23.04. (CVE-2023-34872)");

  script_tag(name:"affected", value:"'poppler' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler97", ver:"0.86.1-0ubuntu1.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler118", ver:"22.02.0-2ubuntu0.2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler126", ver:"22.12.0-2ubuntu1.1", rls:"UBUNTU23.04"))) {
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
