# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3566");
  script_cve_id("CVE-2022-23517", "CVE-2022-23518", "CVE-2022-23519", "CVE-2022-23520");
  script_tag(name:"creation_date", value:"2023-09-14 04:19:42 +0000 (Thu, 14 Sep 2023)");
  script_version("2023-09-14T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-09-14 05:05:34 +0000 (Thu, 14 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-16 19:13:00 +0000 (Fri, 16 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3566)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3566");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3566");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby-rails-html-sanitizer");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-rails-html-sanitizer' package(s) announced via the DLA-3566 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Rails HTML Sanitizers, an HTML sanitization library for Ruby on Rails applications. An attacker could launch cross-site scripting (XSS) and denial-of-service (DoS) attacks through crafted HTML/XML documents.

CVE-2022-23517

Certain configurations use an inefficient regular expression that is susceptible to excessive backtracking when attempting to sanitize certain SVG attributes. This may lead to a denial of service through CPU resource consumption.

CVE-2022-23518

Cross-site scripting via data URIs when used in combination with Loofah >= 2.1.0.

CVE-2022-23519

XSS vulnerability with certain configurations of Rails::Html::Sanitizer may allow an attacker to inject content if the application developer has overridden the sanitizer's allowed tags in either of the following ways: allow both math and style elements, or allow both svg and style elements.

CVE-2022-23520

XSS vulnerability with certain configurations of Rails::Html::Sanitizer due to an incomplete fix of CVE-2022-32209. Rails::Html::Sanitizer may allow an attacker to inject content if the application developer has overridden the sanitizer's allowed tags to allow both select and style elements.

For Debian 10 buster, these problems have been fixed in version 1.0.4-1+deb10u2.

We recommend that you upgrade your ruby-rails-html-sanitizer packages.

For the detailed security status of ruby-rails-html-sanitizer please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-rails-html-sanitizer' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rails-html-sanitizer", ver:"1.0.4-1+deb10u2", rls:"DEB10"))) {
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
