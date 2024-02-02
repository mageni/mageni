# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6538.2");
  script_cve_id("CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870");
  script_tag(name:"creation_date", value:"2024-01-18 04:08:55 +0000 (Thu, 18 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-10 18:15:07 +0000 (Sun, 10 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6538-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6538-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6538-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-10' package(s) announced via the USN-6538-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6538-1 fixed several vulnerabilities in PostgreSQL. This update provides
the corresponding updates for Ubuntu 18.04 LTS.

Original advisory details:

 Jingzhou Fu discovered that PostgreSQL incorrectly handled certain unknown
 arguments in aggregate function calls. A remote attacker could possibly use
 this issue to obtain sensitive information. (CVE-2023-5868)

 Pedro Gallegos discovered that PostgreSQL incorrectly handled modifying
 certain SQL array values. A remote attacker could use this issue to obtain
 sensitive information, or possibly execute arbitrary code. (CVE-2023-5869)

 Hemanth Sandrana and Mahendrakar Srinivasarao discovered that PostgreSQL
 allowed the pg_signal_backend role to signal certain superuser processes,
 contrary to expectations. (CVE-2023-5870)");

  script_tag(name:"affected", value:"'postgresql-10' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-10", ver:"10.23-0ubuntu0.18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-10", ver:"10.23-0ubuntu0.18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
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
