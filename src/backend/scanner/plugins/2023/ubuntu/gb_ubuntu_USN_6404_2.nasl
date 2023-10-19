# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6404.2");
  script_cve_id("CVE-2023-5169", "CVE-2023-5170", "CVE-2023-5171", "CVE-2023-5172", "CVE-2023-5173", "CVE-2023-5175", "CVE-2023-5176", "CVE-2023-5217");
  script_tag(name:"creation_date", value:"2023-10-12 04:08:40 +0000 (Thu, 12 Oct 2023)");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 15:17:00 +0000 (Fri, 29 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6404-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6404-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6404-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2038977");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-6404-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6404-1 fixed vulnerabilities in Firefox. The update introduced
several minor regressions. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across domains, or execute arbitrary code. (CVE-2023-5169,
 CVE-2023-5170, CVE-2023-5171, CVE-2023-5172, CVE-2023-5175, CVE-2023-5176)

 Ronald Crane discovered that Firefox did not properly manage memory when
 non-HTTPS Alternate Services (network.http.altsvc.oe) is enabled. An
 attacker could potentially exploit this issue to cause a denial of service.
 (CVE-2023-5173)

 Clement Lecigne discovered that Firefox did not properly manage memory when
 handling VP8 media stream. An attacker-controlled VP8 media stream could
 lead to a heap buffer overflow in the content process, resulting in a
 denial of service, or possibly execute arbitrary code. (CVE-2023-5217)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"118.0.2+build2-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
