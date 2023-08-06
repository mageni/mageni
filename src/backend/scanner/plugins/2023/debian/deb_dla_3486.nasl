# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3486");
  script_tag(name:"creation_date", value:"2023-07-10 04:22:05 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-3486)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3486");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3486");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ocsinventory-server");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ocsinventory-server' package(s) announced via the DLA-3486 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The source package ocsinventory-server has been updated to address the API change in php-cas due to CVE-2022-39369, see DLA 3485-1 for details.

CAS is an optional authentication mechanism in the binary package ocsinventory-reports, and if used, ocsinventory-reports will stop working until it has been reconfigured:

It now requires the baseURL of to-be-authenticated service to be configured.

For ocsinventory-reports, this is configured with the variable $cas_service_base_url in the file /usr/share/ocsinventory-reports/backend/require/cas.config.php

Warning: regardless of this update, ocsreports-server should only be used in secure and trusted environments.

For Debian 10 buster, this update is available through version 2.5+dfsg1-1+deb10u1.

We recommend that you upgrade your ocsinventory-server packages.

For the detailed security status of ocsinventory-server please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ocsinventory-server' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ocsinventory-reports", ver:"2.5+dfsg1-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ocsinventory-server", ver:"2.5+dfsg1-1+deb10u1", rls:"DEB10"))) {
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
