# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5422");
  script_cve_id("CVE-2022-39286");
  script_tag(name:"creation_date", value:"2023-06-12 04:20:52 +0000 (Mon, 12 Jun 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-28 19:38:00 +0000 (Fri, 28 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-5422)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5422");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5422");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5422");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/jupyter-core");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jupyter-core' package(s) announced via the DSA-5422 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that jupyter-core, the core common functionality for Jupyter projects, could execute arbitrary code in the current working directory while loading configuration files.

For the stable distribution (bullseye), this problem has been fixed in version 4.7.1-1+deb11u1.

We recommend that you upgrade your jupyter-core packages.

For the detailed security status of jupyter-core please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'jupyter-core' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"jupyter", ver:"4.7.1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jupyter-core", ver:"4.7.1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-jupyter-core-doc", ver:"4.7.1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-jupyter-core", ver:"4.7.1-1+deb11u1", rls:"DEB11"))) {
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
