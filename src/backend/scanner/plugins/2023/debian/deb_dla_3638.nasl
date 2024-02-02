# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3638");
  script_cve_id("CVE-2023-44487");
  script_tag(name:"creation_date", value:"2023-11-01 04:20:26 +0000 (Wed, 01 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");

  script_name("Debian: Security Advisory (DLA-3638-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3638-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3638-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/h2o");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'h2o' package(s) announced via the DLA-3638-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been identified in h2o, a high-performance web server with support for HTTP/2.

A security vulnerability CVE-2023-44487 was discovered that could potentially be exploited to disrupt server operation.

The vulnerability in the h2o HTTP/2 server was related to the handling of certain types of HTTP/2 requests. In certain scenarios, an attacker could send a series of malicious requests, causing the server to process them rapidly and exhaust system resources.

The applied upstream patch changes the ABI. Therefore, if your application is built against any shared libraries of h2o, you need to rebuild it. No Debian package is affected.

For Debian 10 buster, this problem has been fixed in version 2.2.5+dfsg2-2+deb10u2.

We recommend that you upgrade your h2o packages.

For the detailed security status of h2o please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'h2o' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"h2o", ver:"2.2.5+dfsg2-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"h2o-doc", ver:"2.2.5+dfsg2-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libh2o-dev", ver:"2.2.5+dfsg2-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libh2o-dev-common", ver:"2.2.5+dfsg2-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libh2o-evloop-dev", ver:"2.2.5+dfsg2-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libh2o-evloop0.13", ver:"2.2.5+dfsg2-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libh2o0.13", ver:"2.2.5+dfsg2-2+deb10u2", rls:"DEB10"))) {
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
