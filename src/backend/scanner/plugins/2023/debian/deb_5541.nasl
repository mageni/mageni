# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5541");
  script_cve_id("CVE-2023-41259", "CVE-2023-41260", "CVE-2023-45024");
  script_tag(name:"creation_date", value:"2023-10-31 04:23:14 +0000 (Tue, 31 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 19:29:46 +0000 (Mon, 13 Nov 2023)");

  script_name("Debian: Security Advisory (DSA-5541-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5541-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5541-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5541");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/request-tracker5");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'request-tracker5' package(s) announced via the DSA-5541-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Request Tracker, an extensible trouble-ticket tracking system.

CVE-2023-41259

Tom Wolters reported that Request Tracker is vulnerable to accepting unvalidated RT email headers in incoming email and the mail-gateway REST interface.

CVE-2023-41260

Tom Wolters reported that Request Tracker is vulnerable to information leakage via response messages returned from requests sent via the mail-gateway REST interface.

CVE-2023-45024

It was reported that Request Tracker is vulnerable to information leakage via transaction searches made by authenticated users in the transaction query builder.

For the stable distribution (bookworm), these problems have been fixed in version 5.0.3+dfsg-3~deb12u2.

We recommend that you upgrade your request-tracker5 packages.

For the detailed security status of request-tracker5 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'request-tracker5' package(s) on Debian 12.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker5", ver:"5.0.3+dfsg-3~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-apache2", ver:"5.0.3+dfsg-3~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-clients", ver:"5.0.3+dfsg-3~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-db-mysql", ver:"5.0.3+dfsg-3~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-db-postgresql", ver:"5.0.3+dfsg-3~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-db-sqlite", ver:"5.0.3+dfsg-3~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-doc-html", ver:"5.0.3+dfsg-3~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-fcgi", ver:"5.0.3+dfsg-3~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-standalone", ver:"5.0.3+dfsg-3~deb12u2", rls:"DEB12"))) {
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
