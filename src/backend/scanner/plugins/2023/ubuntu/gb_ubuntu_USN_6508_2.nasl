# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6508.2");
  script_cve_id("CVE-2020-23804", "CVE-2022-37050", "CVE-2022-37051", "CVE-2022-37052", "CVE-2022-38349");
  script_tag(name:"creation_date", value:"2023-11-30 04:08:47 +0000 (Thu, 30 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-25 19:08:14 +0000 (Fri, 25 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6508-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6508-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6508-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2045027");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the USN-6508-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6508-1 fixed vulnerabilities in poppler. The update introduced
one minor regression in Ubuntu 18.04 LTS. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that poppler incorrectly handled certain malformed PDF
 files. If a user or an automated system were tricked into opening a
 specially crafted PDF file, a remote attacker could possibly use this
 issue to cause a denial of service. This issue only affected Ubuntu 16.04
 LTS, Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-23804)

 It was discovered that poppler incorrectly handled certain malformed PDF
 files. If a user or an automated system were tricked into opening a
 specially crafted PDF file, a remote attacker could possibly use this
 issue to cause a denial of service. (CVE-2022-37050, CVE-2022-37051,
 CVE-2022-37052, CVE-2022-38349)");

  script_tag(name:"affected", value:"'poppler' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler73", ver:"0.62.0-2ubuntu2.14+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.62.0-2ubuntu2.14+esm3", rls:"UBUNTU18.04 LTS"))) {
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
