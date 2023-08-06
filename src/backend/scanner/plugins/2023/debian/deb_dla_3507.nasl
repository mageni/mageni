# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3507");
  script_cve_id("CVE-2023-35936");
  script_tag(name:"creation_date", value:"2023-07-26 04:28:15 +0000 (Wed, 26 Jul 2023)");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-12 18:09:00 +0000 (Wed, 12 Jul 2023)");

  script_name("Debian: Security Advisory (DLA-3507)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3507");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3507");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pandoc");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pandoc' package(s) announced via the DLA-3507 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Arbitrary file write vulnerabilities were discovered in pandoc, an Haskell library and CLI tool for converting from one markup format to another. These vulnerabilities can be triggered by providing a specially crafted image element in the input when generating files using the --extract-media option or outputting to PDF format, and allow an attacker to create or overwrite arbitrary files on the system (depending on the privileges of the process running pandoc).

CVE-2023-35936

Entroy C discovered that by appending percent-encoded directory components at the end of malicious data: URI, an attacker could trick pandoc into creating or overwriting arbitrary files on the system.

CVE-2023-38745

Guilhem Moulin discovered that the upstream fix for CVE-2023-35936 was incomplete, namely that the vulnerability remained when encoding '%' characters as '%25'.

For Debian 10 buster, these problems have been fixed in version 2.2.1-3+deb10u1.

We recommend that you upgrade your pandoc packages.

For the detailed security status of pandoc please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'pandoc' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libghc-pandoc-dev", ver:"2.2.1-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libghc-pandoc-doc", ver:"2.2.1-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libghc-pandoc-prof", ver:"2.2.1-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pandoc", ver:"2.2.1-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pandoc-data", ver:"2.2.1-3+deb10u1", rls:"DEB10"))) {
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
