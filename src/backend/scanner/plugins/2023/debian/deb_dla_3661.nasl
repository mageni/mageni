# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3661");
  script_cve_id("CVE-2023-6204", "CVE-2023-6205", "CVE-2023-6206", "CVE-2023-6207", "CVE-2023-6208", "CVE-2023-6209", "CVE-2023-6212");
  script_tag(name:"creation_date", value:"2023-11-24 04:19:34 +0000 (Fri, 24 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 19:30:41 +0000 (Tue, 28 Nov 2023)");

  script_name("Debian: Security Advisory (DLA-3661-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3661-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3661-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/firefox-esr");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firefox-esr' package(s) announced via the DLA-3661-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Mozilla Firefox web browser, which could potentially result in the execution of arbitrary code, information leaks or clickjacking.

For Debian 10 buster, these problems have been fixed in version 115.5.0esr-1~deb10u1.

We recommend that you upgrade your firefox-esr packages.

For the detailed security status of firefox-esr please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ach", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-af", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-all", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-an", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ar", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ast", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-az", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-be", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bg", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bn", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-br", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bs", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ca", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ca-valencia", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cak", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cs", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cy", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-da", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-de", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-dsb", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-el", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-ca", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-gb", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eo", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-ar", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-cl", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-es", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-mx", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-et", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eu", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fa", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ff", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fi", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fr", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fur", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fy-nl", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ga-ie", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gd", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gl", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gn", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gu-in", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-he", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hi-in", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hr", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hsb", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hu", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hy-am", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ia", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-id", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-is", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-it", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ja", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ka", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kab", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kk", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-km", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kn", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ko", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lij", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lt", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lv", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mk", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mr", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ms", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-my", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nb-no", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ne-np", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nl", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nn-no", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-oc", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pa-in", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pl", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-br", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-pt", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-rm", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ro", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ru", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sc", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sco", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-si", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sk", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sl", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-son", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sq", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sr", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sv-se", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-szl", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ta", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-te", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tg", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-th", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tl", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tr", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-trs", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uk", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ur", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uz", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-vi", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-xh", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-cn", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-tw", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ach", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-af", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-all", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-an", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ar", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ast", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-az", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-be", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bg", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bn", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-br", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bs", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ca", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ca-valencia", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cak", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cs", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cy", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-da", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-de", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-dsb", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-el", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-ca", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-gb", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eo", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-ar", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-cl", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-es", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-mx", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-et", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eu", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fa", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ff", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fi", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fr", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fur", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fy-nl", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ga-ie", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gd", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gl", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gn", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gu-in", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-he", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hi-in", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hr", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hsb", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hu", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hy-am", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ia", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-id", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-is", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-it", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ja", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ka", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kab", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kk", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-km", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kn", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ko", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lij", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lt", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lv", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mk", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mr", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ms", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-my", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nb-no", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ne-np", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nl", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nn-no", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-oc", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pa-in", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pl", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-br", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-pt", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-rm", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ro", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ru", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sc", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sco", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-si", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sk", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sl", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-son", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sq", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sr", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sv-se", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-szl", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ta", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-te", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-tg", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-th", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-tl", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-tr", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-trs", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uk", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ur", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uz", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-vi", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-xh", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-cn", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-tw", ver:"1:115.5.0esr-1~deb10u1", rls:"DEB10"))) {
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
