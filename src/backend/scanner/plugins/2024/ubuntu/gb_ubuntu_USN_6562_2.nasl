# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6562.2");
  script_cve_id("CVE-2023-6135", "CVE-2023-6856", "CVE-2023-6857", "CVE-2023-6858", "CVE-2023-6859", "CVE-2023-6860", "CVE-2023-6861", "CVE-2023-6863", "CVE-2023-6864", "CVE-2023-6865", "CVE-2023-6866", "CVE-2023-6867", "CVE-2023-6869", "CVE-2023-6871", "CVE-2023-6872", "CVE-2023-6873");
  script_tag(name:"creation_date", value:"2024-01-12 04:09:10 +0000 (Fri, 12 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 10:28:50 +0000 (Fri, 22 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6562-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6562-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6562-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2048961");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-6562-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6562-1 fixed vulnerabilities in Firefox. The update introduced
several minor regressions. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across domains, or execute arbitrary code.(CVE-2023-6865,
 CVE-2023-6857, CVE-2023-6858, CVE-2023-6859, CVE-2023-6866, CVE-2023-6867,
 CVE-2023-6861, CVE-2023-6869, CVE-2023-6871, CVE-2023-6872, CVE-2023-6863,
 CVE-2023-6864, CVE-2023-6873)

 DoHyun Lee discovered that Firefox did not properly manage memory when used
 on systems with the Mesa VM driver. An attacker could potentially exploit
 this issue to execute arbitrary code. (CVE-2023-6856)

 George Pantela and Hubert Kario discovered that Firefox using multiple NSS
 NIST curves which were susceptible to a side-channel attack known as
 'Minerva'. An attacker could potentially exploit this issue to obtain
 sensitive information. (CVE-2023-6135)

 Andrew Osmond discovered that Firefox did not properly validate the textures
 produced by remote decoders. An attacker could potentially exploit this
 issue to escape the sandbox. (CVE-2023-6860)");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"121.0.1+build1-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
