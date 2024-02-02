# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6475.1");
  script_cve_id("CVE-2014-3225", "CVE-2017-1000469", "CVE-2018-1000225", "CVE-2018-1000226", "CVE-2018-10931", "CVE-2021-40323", "CVE-2021-40324", "CVE-2021-40325", "CVE-2021-45082", "CVE-2021-45083", "CVE-2022-0860");
  script_tag(name:"creation_date", value:"2023-11-14 04:08:31 +0000 (Tue, 14 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 20:25:00 +0000 (Tue, 12 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-6475-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6475-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6475-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cobbler' package(s) announced via the USN-6475-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Cobbler did not properly handle user input, which
could result in an absolute path traversal. An attacker could possibly
use this issue to read arbitrary files. (CVE-2014-3225)

It was discovered that Cobbler did not properly handle user input, which
could result in command injection. An attacker could possibly use this
issue to execute arbitrary code with high privileges.
(CVE-2017-1000469, CVE-2021-45082)

It was discovered that Cobbler did not properly hide private functions in
a class. A remote attacker could possibly use this issue to gain high
privileges and upload files to an arbitrary location.
(CVE-2018-10931, CVE-2018-1000225, CVE-2018-1000226)

Nicolas Chatelain discovered that Cobbler did not properly handle user
input, which could result in log poisoning. A remote attacker could
possibly use this issue to bypass authorization, write in an arbitrary
file, or execute arbitrary code.
(CVE-2021-40323, CVE-2021-40324, CVE-2021-40325)

It was discovered that Cobbler did not properly handle file permissions
during package install or update operations. An attacker could possibly
use this issue to perform a privilege escalation attack. (CVE-2021-45083)

It was discovered that Cobbler did not properly process credentials for
expired accounts. An attacker could possibly use this issue to login to
the platform with an expired account or password. (CVE-2022-0860)");

  script_tag(name:"affected", value:"'cobbler' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cobbler", ver:"2.4.1-0ubuntu2+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cobbler-common", ver:"2.4.1-0ubuntu2+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cobbler-web", ver:"2.4.1-0ubuntu2+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"koan", ver:"2.4.1-0ubuntu2+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-cobbler", ver:"2.4.1-0ubuntu2+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-koan", ver:"2.4.1-0ubuntu2+esm1", rls:"UBUNTU16.04 LTS"))) {
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
