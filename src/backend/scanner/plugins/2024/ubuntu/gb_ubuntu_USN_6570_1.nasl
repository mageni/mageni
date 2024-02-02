# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6570.1");
  script_cve_id("CVE-2023-5869", "CVE-2023-5870");
  script_tag(name:"creation_date", value:"2024-01-10 04:09:13 +0000 (Wed, 10 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-10 18:15:07 +0000 (Sun, 10 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6570-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6570-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6570-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-9.5' package(s) announced via the USN-6570-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pedro Gallegos discovered that PostgreSQL incorrectly handled modifying
certain SQL array values. A remote attacker could use this issue to obtain
sensitive information, or possibly execute arbitrary code. (CVE-2023-5869)

Hemanth Sandrana and Mahendrakar Srinivasarao discovered that PostgreSQL
allowed the pg_signal_backend role to signal certain superuser processes,
contrary to expectations. (CVE-2023-5870)");

  script_tag(name:"affected", value:"'postgresql-9.5' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.5", ver:"9.5.25-0ubuntu0.16.04.1+esm6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-9.5", ver:"9.5.25-0ubuntu0.16.04.1+esm6", rls:"UBUNTU16.04 LTS"))) {
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
