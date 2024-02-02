# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.354.01");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2023-12-21 04:21:02 +0000 (Thu, 21 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-354-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.0|14\.1|14\.2|15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2023-354-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.462318");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-48795");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proftpd' package(s) announced via the SSA:2023-354-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New proftpd packages are available for Slackware 14.0, 14.1, 14.2, 15.0,
and -current to fix a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/proftpd-1.3.8b-i586-1_slack15.0.txz: Upgraded.
 This update fixes a security issue:
 mod_sftp: implemented mitigations for 'Terrapin' SSH attack.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'proftpd' package(s) on Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware 15.0, Slackware current.");

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

if(release == "SLK14.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-i486-1_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-x86_64-1_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-i486-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-x86_64-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-i586-1_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-x86_64-1_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.8b-x86_64-1", rls:"SLKcurrent"))) {
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
