# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3450");
  script_cve_id("CVE-2021-33621", "CVE-2022-28739");
  script_tag(name:"creation_date", value:"2023-06-20 04:25:15 +0000 (Tue, 20 Jun 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-22 21:04:00 +0000 (Tue, 22 Nov 2022)");

  script_name("Debian: Security Advisory (DLA-3450)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3450");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3450");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby2.5");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby2.5' package(s) announced via the DLA-3450 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A couple of security issues were discovered in ruby2.5, the Ruby interpreter, and are as follows

CVE-2021-33621

Hiroshi Tokumaru discovered that Ruby did not properly handle certain user input for applications the generate HTTP responses using cgi gem. An attacker could possibly use this issue to maliciously modify the response a user would receive from a vulnerable application.

CVE-2022-28739

It was discovered that Ruby incorrectly handled certain inputs. An attacker could possibly use this issue to expose sensitive information.

For Debian 10 buster, these problems have been fixed, along with the regressions caused by the last Ruby update, in version 2.5.5-3+deb10u6.

We recommend that you upgrade your ruby2.5 packages.

For the detailed security status of ruby2.5 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby2.5' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.5", ver:"2.5.5-3+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5", ver:"2.5.5-3+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5-dev", ver:"2.5.5-3+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5-doc", ver:"2.5.5-3+deb10u6", rls:"DEB10"))) {
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
