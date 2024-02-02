# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3637");
  script_cve_id("CVE-2023-5721", "CVE-2023-5724", "CVE-2023-5725", "CVE-2023-5728", "CVE-2023-5730", "CVE-2023-5732");
  script_tag(name:"creation_date", value:"2023-10-30 04:23:36 +0000 (Mon, 30 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 19:54:34 +0000 (Wed, 01 Nov 2023)");

  script_name("Debian: Security Advisory (DLA-3637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3637-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3637-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/thunderbird");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'thunderbird' package(s) announced via the DLA-3637-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird, which could result in denial of service or the execution of arbitrary code.

For Debian 10 buster, these problems have been fixed in version 1:115.4.1-1~deb10u1.

We recommend that you upgrade your thunderbird packages.

For the detailed security status of thunderbird please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-af", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-all", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ar", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ast", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-be", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-bg", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-br", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ca", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-cak", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-cs", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-cy", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-da", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-de", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-dsb", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-el", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-en-ca", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-en-gb", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-es-ar", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-es-es", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-es-mx", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-et", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-eu", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-fi", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-fr", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-fy-nl", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ga-ie", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-gd", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-gl", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-he", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hr", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hsb", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hu", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hy-am", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-id", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-is", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-it", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ja", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ka", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-kab", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-kk", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ko", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-lt", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-lv", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ms", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-nb-no", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-nl", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-nn-no", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pa-in", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pl", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pt-br", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pt-pt", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-rm", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ro", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ru", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sk", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sl", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sq", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sr", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sv-se", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-th", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-tr", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-uk", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-uz", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-vi", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-zh-cn", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-zh-tw", ver:"1:115.4.1-1~deb10u1", rls:"DEB10"))) {
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
