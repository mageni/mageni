# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.216.02");
  script_cve_id("CVE-2022-2127", "CVE-2023-3347", "CVE-2023-34966", "CVE-2023-34967", "CVE-2023-34968");
  script_tag(name:"creation_date", value:"2023-08-07 04:14:43 +0000 (Mon, 07 Aug 2023)");
  script_version("2023-08-08T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-08-08 05:06:11 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 19:15:00 +0000 (Mon, 31 Jul 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-216-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2023-216-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.476615");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-2127");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3347");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-34966");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-34967");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-34968");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-2127.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-3347.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-34966.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-34967.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-34968.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SSA:2023-216-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New samba packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/samba-4.18.5-i586-1_slack15.0.txz: Upgraded.
 PLEASE NOTE: We are taking the unusual step of moving to the latest Samba
 branch because Windows has made changes that break Samba 4.15.x. The last
 4.15.x will be retained in /pasture as a fallback. There may be some
 required configuration changes with this, but we've kept using MIT Kerberos
 to try to have the behavior change as little as possible. Upgrade carefully.
 This update fixes security issues:
 When winbind is used for NTLM authentication, a maliciously crafted request
 can trigger an out-of-bounds read in winbind and possibly crash it.
 SMB2 packet signing is not enforced if an admin configured
 'server signing = required' or for SMB2 connections to Domain Controllers
 where SMB2 packet signing is mandatory.
 An infinite loop bug in Samba's mdssvc RPC service for Spotlight can be
 triggered by an unauthenticated attacker by issuing a malformed RPC request.
 Missing type validation in Samba's mdssvc RPC service for Spotlight can be
 used by an unauthenticated attacker to trigger a process crash in a shared
 RPC mdssvc worker process.
 As part of the Spotlight protocol Samba discloses the server-side absolute
 path of shares and files and directories in search results.
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
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'samba' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.18.5-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.18.5-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.18.5-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.18.5-x86_64-1", rls:"SLKcurrent"))) {
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
