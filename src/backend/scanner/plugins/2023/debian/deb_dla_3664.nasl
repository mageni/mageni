# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3664");
  script_cve_id("CVE-2023-46734");
  script_tag(name:"creation_date", value:"2023-11-27 04:28:29 +0000 (Mon, 27 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-10 18:15:09 +0000 (Fri, 10 Nov 2023)");

  script_name("Debian: Security Advisory (DLA-3664-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3664-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3664-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/symfony");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DLA-3664-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pierre Rudloff discovered a potential XSS vulnerability in Symfony, a PHP framework. Some Twig filters in CodeExtension use `is_safe=html` but do not actually ensure their input is safe. Symfony now escapes the output of the affected filters.

For Debian 10 buster, this problem has been fixed in version 3.4.22+dfsg-2+deb10u3.

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

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-asset", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-browser-kit", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-cache", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-class-loader", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-config", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-console", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-css-selector", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug-bundle", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dependency-injection", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-doctrine-bridge", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dom-crawler", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dotenv", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-event-dispatcher", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-expression-language", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-filesystem", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-finder", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-form", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-framework-bundle", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-foundation", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-kernel", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-inflector", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-intl", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-ldap", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-lock", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-monolog-bridge", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-options-resolver", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-phpunit-bridge", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-process", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-access", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-info", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-proxy-manager-bridge", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-routing", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-bundle", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-core", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-csrf", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-guard", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-http", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-serializer", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-stopwatch", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-templating", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-translation", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bridge", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bundle", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-validator", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-var-dumper", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-link", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-profiler-bundle", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-server-bundle", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-workflow", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-yaml", ver:"3.4.22+dfsg-2+deb10u3", rls:"DEB10"))) {
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
