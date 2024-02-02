# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3671");
  script_cve_id("CVE-2023-3550", "CVE-2023-45362", "CVE-2023-45363");
  script_tag(name:"creation_date", value:"2023-11-29 04:30:17 +0000 (Wed, 29 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-12 16:00:30 +0000 (Thu, 12 Oct 2023)");

  script_name("Debian: Security Advisory (DLA-3671-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3671-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3671-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mediawiki");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki' package(s) announced via the DLA-3671-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in mediawiki, a website engine for collaborative work, that could lead to information disclosure, privilege escalation, or denial of service.

CVE-2023-3550

Carlos Bello reported a stored cross-site scripting (XSS) vulnerability when uploading crafted XML file to Special:Upload, which can lead to privilege escalation. (However .xml file uploads are not allowed in the default configuration.)

CVE-2023-45362

Tobias Frei discovered that diff-multi-sameuser ('X intermediate revisions by the same user not shown') ignores username suppression, which can lead to information leak.

CVE-2023-45363

It was discovered that querying pages redirected to other variants with redirects and converttitles parameters set would cause a denial of service (unbounded loop and RequestTimeoutException).

For Debian 10 buster, these problems have been fixed in version 1:1.31.16-1+deb10u7.

We recommend that you upgrade your mediawiki packages.

For the detailed security status of mediawiki please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki", ver:"1:1.31.16-1+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-classes", ver:"1:1.31.16-1+deb10u7", rls:"DEB10"))) {
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
