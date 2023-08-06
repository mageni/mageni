# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3493");
  script_cve_id("CVE-2021-21424", "CVE-2022-24894", "CVE-2022-24895");
  script_tag(name:"creation_date", value:"2023-07-12 04:29:37 +0000 (Wed, 12 Jul 2023)");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-15 14:25:00 +0000 (Wed, 15 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-3493)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3493");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3493");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/symfony");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DLA-3493 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were found in symfony, a PHP framework for web and console applications and a set of reusable PHP components, which could lead to information disclosure or impersonation.

CVE-2021-21424

James Isaac, Mathias Brodala and Laurent Minguet discovered that it was possible to enumerate users without relevant permissions due to different exception messages depending on whether the user existed or not. It was also possible to enumerate users by using a timing attack, by comparing time elapsed when authenticating an existing user and authenticating a non-existing user.

403s are now returned whether the user exists or not if a user cannot switch to a user or if the user does not exist.

CVE-2022-24894

Soner Sayakci discovered that when the Symfony HTTP cache system is enabled, the response header might be stored with a Set-Cookie header and returned to some other clients, thereby allowing an attacker to retrieve the victim's session.

The HttpStore constructor now takes a parameter containing a list of private headers that are removed from the HTTP response headers. The default value for this parameter is Set-Cookie, but it can be overridden or extended by the application.

CVE-2022-24895

Marco Squarcina discovered that CSRF tokens weren't cleared upon login, which could enable same-site attackers to bypass the CSRF protection mechanism by performing an attack similar to a session-fixation.

For Debian 10 buster, these problems have been fixed in version 3.4.22+dfsg-2+deb10u2.

We recommend that you upgrade your symfony packages.

For the detailed security status of symfony please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-asset", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-browser-kit", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-cache", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-class-loader", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-config", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-console", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-css-selector", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug-bundle", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dependency-injection", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-doctrine-bridge", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dom-crawler", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dotenv", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-event-dispatcher", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-expression-language", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-filesystem", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-finder", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-form", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-framework-bundle", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-foundation", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-kernel", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-inflector", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-intl", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-ldap", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-lock", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-monolog-bridge", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-options-resolver", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-phpunit-bridge", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-process", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-access", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-info", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-proxy-manager-bridge", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-routing", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-bundle", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-core", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-csrf", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-guard", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-http", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-serializer", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-stopwatch", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-templating", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-translation", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bridge", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bundle", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-validator", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-var-dumper", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-link", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-profiler-bundle", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-server-bundle", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-workflow", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-yaml", ver:"3.4.22+dfsg-2+deb10u2", rls:"DEB10"))) {
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
