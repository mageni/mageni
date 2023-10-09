# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5484");
  script_cve_id("CVE-2023-38633");
  script_tag(name:"creation_date", value:"2023-08-28 04:20:11 +0000 (Mon, 28 Aug 2023)");
  script_version("2023-08-28T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-08-28 05:05:30 +0000 (Mon, 28 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-16 19:41:00 +0000 (Wed, 16 Aug 2023)");

  script_name("Debian: Security Advisory (DSA-5484)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5484");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5484");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5484");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/librsvg");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'librsvg' package(s) announced via the DSA-5484 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zac Sims discovered a directory traversal in the URL decoder of librsvg, a SAX-based renderer library for SVG files, which could result in read of arbitrary files when processing a specially crafted SVG file with an XInclude element.

For the oldstable distribution (bullseye), this problem has been fixed in version 2.50.3+dfsg-1+deb11u1.

For the stable distribution (bookworm), this problem has been fixed in version 2.54.7+dfsg-1~deb12u1.

We recommend that you upgrade your librsvg packages.

For the detailed security status of librsvg please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'librsvg' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-rsvg-2.0", ver:"2.50.3+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-2", ver:"2.50.3+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-bin", ver:"2.50.3+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-common", ver:"2.50.3+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-dev", ver:"2.50.3+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-doc", ver:"2.50.3+dfsg-1+deb11u1", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-rsvg-2.0", ver:"2.54.7+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-2", ver:"2.54.7+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-bin", ver:"2.54.7+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-common", ver:"2.54.7+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-dev", ver:"2.54.7+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-doc", ver:"2.54.7+dfsg-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-tests", ver:"2.54.7+dfsg-1~deb12u1", rls:"DEB12"))) {
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
