# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3494");
  script_cve_id("CVE-2023-34246");
  script_tag(name:"creation_date", value:"2023-07-13 04:30:40 +0000 (Thu, 13 Jul 2023)");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 16:38:00 +0000 (Wed, 21 Jun 2023)");

  script_name("Debian: Security Advisory (DLA-3494)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3494");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3494");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-doorkeeper' package(s) announced via the DLA-3494 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an issue in ruby-doorkeeper, an OAuth2 provider for Ruby on Rails applications. Doorkeeper automatically processed authorization requests without user consent for public clients that have been previously approved, but public clients are inherently vulnerable to impersonation as their identity cannot be assured.

CVE-2023-34246

Doorkeeper is an OAuth 2 provider for Ruby on Rails / Grape. Prior to version 5.6.6, Doorkeeper automatically processes authorization requests without user consent for public clients that have been previous approved. Public clients are inherently vulnerable to impersonation, their identity cannot be assured. This issue is fixed in version 5.6.6.

For Debian 10 Buster, this problem has been fixed in version 4.4.2-1+deb10u1.

We recommend that you upgrade your ruby-doorkeeper packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-doorkeeper' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-doorkeeper", ver:"4.4.2-1+deb10u1", rls:"DEB10"))) {
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
