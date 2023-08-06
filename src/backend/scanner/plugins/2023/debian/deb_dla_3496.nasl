# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3496");
  script_cve_id("CVE-2023-28862");
  script_tag(name:"creation_date", value:"2023-07-17 04:26:11 +0000 (Mon, 17 Jul 2023)");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-11 06:05:00 +0000 (Tue, 11 Apr 2023)");

  script_name("Debian: Security Advisory (DLA-3496)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3496");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3496");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/lemonldap-ng");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lemonldap-ng' package(s) announced via the DLA-3496 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Issues were discovered in Lemonldap::NG, an OpenID-Connect, CAS and SAML compatible Web-SSO system, which could lead to impersonation of users with a second factor authentication.

Weak session ID generation in the AuthBasic handler and incorrect failure handling during a password check allow attackers to bypass 2FA verification. Any plugin that tries to deny session creation after the store step does not deny an AuthBasic session.

Using the AuthBasic handler is now refused for users with a second factor. Admins who are *absolutely sure* that such accounts should be able to use AuthBasic handlers (which are password only) can append and not $ENV{AuthBasic} to the 2FA activation rules.

For Debian 10 buster, these problems have been fixed in version 2.0.2+ds-7+deb10u9.

We recommend that you upgrade your lemonldap-ng packages.

For the detailed security status of lemonldap-ng please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'lemonldap-ng' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng", ver:"2.0.2+ds-7+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-doc", ver:"2.0.2+ds-7+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-fastcgi-server", ver:"2.0.2+ds-7+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-handler", ver:"2.0.2+ds-7+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-uwsgi-app", ver:"2.0.2+ds-7+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-common-perl", ver:"2.0.2+ds-7+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-handler-perl", ver:"2.0.2+ds-7+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-manager-perl", ver:"2.0.2+ds-7+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-portal-perl", ver:"2.0.2+ds-7+deb10u9", rls:"DEB10"))) {
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
