# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6546.2");
  script_cve_id("CVE-2023-6185", "CVE-2023-6186");
  script_tag(name:"creation_date", value:"2023-12-15 04:08:53 +0000 (Fri, 15 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-14 14:41:30 +0000 (Thu, 14 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6546-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6546-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6546-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice' package(s) announced via the USN-6546-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6546-1 fixed vulnerabilities in LibreOffice. This update provides the
corresponding updates for Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.

Original advisory details:

 Reginaldo Silva discovered that LibreOffice incorrectly handled filenames
 when passing embedded videos to GStreamer. If a user were tricked into
 opening a specially crafted file, a remote attacker could possibly use this
 issue to execute arbitrary GStreamer plugins. (CVE-2023-6185)

 Reginaldo Silva discovered that LibreOffice incorrectly handled certain
 non-typical hyperlinks. If a user were tricked into opening a specially
 crafted file, a remote attacker could possibly use this issue to execute
 arbitrary scripts. (CVE-2023-6186)");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"1:6.4.7-0ubuntu0.20.04.9", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"1:7.3.7-0ubuntu0.22.04.4", rls:"UBUNTU22.04 LTS"))) {
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
