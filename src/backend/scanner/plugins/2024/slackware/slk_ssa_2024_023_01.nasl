# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.023.01");
  script_cve_id("CVE-2024-0741", "CVE-2024-0742", "CVE-2024-0746", "CVE-2024-0747", "CVE-2024-0749", "CVE-2024-0750", "CVE-2024-0751", "CVE-2024-0753", "CVE-2024-0755");
  script_tag(name:"creation_date", value:"2024-01-24 04:20:18 +0000 (Wed, 24 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:49 +0000 (Mon, 29 Jan 2024)");

  script_name("Slackware: Security Advisory (SSA:2024-023-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2024-023-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.393816");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0741");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0742");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0746");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0747");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0749");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0750");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0751");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0753");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0755");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/115.7.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/advisories/mfsa2024-02/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox' package(s) announced via the SSA:2024-023-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-firefox packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/mozilla-firefox-115.7.0esr-i686-1_slack15.0.txz: Upgraded.
 This update contains security fixes and improvements.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"115.7.0esr-i686-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"115.7.0esr-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"115.7.0esr-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"115.7.0esr-x86_64-1", rls:"SLKcurrent"))) {
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
