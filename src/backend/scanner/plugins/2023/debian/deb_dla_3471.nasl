# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3471");
  script_cve_id("CVE-2023-31130", "CVE-2023-32067");
  script_tag(name:"creation_date", value:"2023-06-27 04:23:27 +0000 (Tue, 27 Jun 2023)");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 13:09:00 +0000 (Thu, 01 Jun 2023)");

  script_name("Debian: Security Advisory (DLA-3471)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3471");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3471");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/c-ares");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'c-ares' package(s) announced via the DLA-3471 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vunerabilities were discovered in c-ares, an asynchronous name resolver library:

CVE-2023-31130

ares_inet_net_pton() is found to be vulnerable to a buffer underflow for certain ipv6 addresses, in particular '0::00:00:00/2' was found to cause an issue. c-ares only uses this function internally for configuration purposes, however external usage for other purposes may cause more severe issues.

CVE-2023-32067

Target resolver may erroneously interprets a malformed UDP packet with a length of 0 as a graceful shutdown of the connection, which could cause a denial of service.

For Debian 10 buster, these problems have been fixed in version 1.14.0-1+deb10u3.

We recommend that you upgrade your c-ares packages.

For the detailed security status of c-ares please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'c-ares' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libc-ares-dev", ver:"1.14.0-1+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-ares2", ver:"1.14.0-1+deb10u3", rls:"DEB10"))) {
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
