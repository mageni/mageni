# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6541.2");
  script_cve_id("CVE-2023-4806", "CVE-2023-4813", "CVE-2023-5156");
  script_tag(name:"creation_date", value:"2024-01-11 04:09:03 +0000 (Thu, 11 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-26 15:02:42 +0000 (Tue, 26 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6541-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6541-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6541-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2047155");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the USN-6541-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6541-1 fixed vulnerabilities in the GNU C Library. Unfortunately,
changes made to allow proper application of the fix for CVE-2023-4806 in
Ubuntu 22.04 LTS introduced an issue in the NSCD service IPv6 processing
functionalities. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the GNU C Library was not properly handling certain
 memory operations. An attacker could possibly use this issue to cause a
 denial of service (application crash). (CVE-2023-4806, CVE-2023-4813)

 It was discovered that the GNU C library was not properly implementing a
 fix for CVE-2023-4806 in certain cases, which could lead to a memory leak.
 An attacker could possibly use this issue to cause a denial of service
 (application crash). This issue only affected Ubuntu 22.04 LTS and Ubuntu
 23.04. (CVE-2023-5156)");

  script_tag(name:"affected", value:"'glibc' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libc-bin", ver:"2.35-0ubuntu3.6", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.35-0ubuntu3.6", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nscd", ver:"2.35-0ubuntu3.6", rls:"UBUNTU22.04 LTS"))) {
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
