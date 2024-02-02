# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5572");
  script_cve_id("CVE-2023-47272");
  script_tag(name:"creation_date", value:"2023-12-04 12:43:42 +0000 (Mon, 04 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 15:22:50 +0000 (Tue, 14 Nov 2023)");

  script_name("Debian: Security Advisory (DSA-5572-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5572-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5572-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5572");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/roundcube");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'roundcube' package(s) announced via the DSA-5572-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rene Rehme discovered that roundcube, a skinnable AJAX based webmail solution for IMAP servers, did not properly set headers when handling attachments. This would allow an attacker to load arbitrary JavaScript code.

For the oldstable distribution (bullseye), this problem has been fixed in version 1.4.15+dfsg.1-1~deb11u2.

For the stable distribution (bookworm), this problem has been fixed in version 1.6.5+dfsg-1~deb12u1.

We recommend that you upgrade your roundcube packages.

For the detailed security status of roundcube please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'roundcube' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.4.15+dfsg.1-1~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.4.15+dfsg.1-1~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-mysql", ver:"1.4.15+dfsg.1-1~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-pgsql", ver:"1.4.15+dfsg.1-1~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-plugins", ver:"1.4.15+dfsg.1-1~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-sqlite3", ver:"1.4.15+dfsg.1-1~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.6.5+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.6.5+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-mysql", ver:"1.6.5+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-pgsql", ver:"1.6.5+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-plugins", ver:"1.6.5+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-sqlite3", ver:"1.6.5+dfsg-1~deb12u1", rls:"DEB12"))) {
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
