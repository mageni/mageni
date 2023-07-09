# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6178.1");
  script_cve_id("CVE-2019-6246", "CVE-2021-44960");
  script_tag(name:"creation_date", value:"2023-06-20 04:09:27 +0000 (Tue, 20 Jun 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-30 14:56:00 +0000 (Wed, 30 Jan 2019)");

  script_name("Ubuntu: Security Advisory (USN-6178-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6178-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6178-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'svgpp' package(s) announced via the USN-6178-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that in SVG++ library that the demo application incorrectly
managed memory resulting in a memory access violation
under certain circumstances. An attacker could possibly use this issue
to leak memory information or run a denial of service attack.
This issue only affected Ubuntu 18.04 LTS. (CVE-2019-6246)

It was discovered that in SVG++ library that the demo application
incorrectly handled null pointers under certain circumstances.
An attacker could possibly use this issue to cause
denial of service, leak memory information or manipulate
program execution flow. (CVE-2021-44960)");

  script_tag(name:"affected", value:"'svgpp' package(s) on Ubuntu 18.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsvgpp-dev", ver:"1.2.3+dfsg1-3ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsvgpp-dev", ver:"1.3.0+dfsg1-3ubuntu2.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libsvgpp-dev", ver:"1.3.0+dfsg1-3ubuntu2.22.10.1", rls:"UBUNTU22.10"))) {
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
