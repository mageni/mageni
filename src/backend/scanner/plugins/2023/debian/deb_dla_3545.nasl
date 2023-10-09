# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3545");
  script_cve_id("CVE-2021-23385");
  script_tag(name:"creation_date", value:"2023-08-29 04:19:52 +0000 (Tue, 29 Aug 2023)");
  script_version("2023-08-29T05:06:28+0000");
  script_tag(name:"last_modification", value:"2023-08-29 05:06:28 +0000 (Tue, 29 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-09 12:47:00 +0000 (Tue, 09 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-3545)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3545");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3545");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/flask-security");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'flask-security' package(s) announced via the DLA-3545 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that when using the get_post_logout_redirect and get_post_login_redirect functions in flask-security, an implementation of simple security for Flask apps, it is possible to bypass URL validation and redirect a user to an arbitrary URL by providing multiple back slashes such as evil.com/path.

This vulnerability is exploitable only if an alternative WSGI server other than Werkzeug is used, or the default behaviour of Werkzeug is modified using 'autocorrect_location_headerulse.

For Debian 10 buster, this problem has been fixed in version 1.7.5-2+deb10u1.

We recommend that you upgrade your flask-security packages.

For the detailed security status of flask-security please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'flask-security' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-flask-security", ver:"1.7.5-2+deb10u1", rls:"DEB10"))) {
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
