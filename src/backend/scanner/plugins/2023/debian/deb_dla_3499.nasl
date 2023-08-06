# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3499");
  script_cve_id("CVE-2021-39191", "CVE-2022-23527");
  script_tag(name:"creation_date", value:"2023-07-19 04:25:50 +0000 (Wed, 19 Jul 2023)");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-16 20:50:00 +0000 (Fri, 16 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3499)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3499");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3499");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libapache2-mod-auth-openidc");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libapache2-mod-auth-openidc' package(s) announced via the DLA-3499 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Open Redirect vulnerabilities were found in libapache2-mod-auth-openidc, OpenID Connect Relying Party implementation for Apache, which could lead to information disclosure via phishing attacks.

CVE-2021-39191

The 3rd-party init SSO functionality of mod_auth_openidc was reported to be vulnerable to an open redirect attack by supplying a crafted URL in the target_link_uri parameter.

CVE-2022-23527

When providing a logout parameter to the redirect URI, mod_auth_openidc failed to properly check for URLs starting with '/t', leading to an open redirect.

For Debian 10 buster, these problems have been fixed in version 2.3.10.2-1+deb10u3.

We recommend that you upgrade your libapache2-mod-auth-openidc packages.

For the detailed security status of libapache2-mod-auth-openidc please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libapache2-mod-auth-openidc' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-auth-openidc", ver:"2.3.10.2-1+deb10u3", rls:"DEB10"))) {
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
