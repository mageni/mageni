# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.200.02");
  script_cve_id("CVE-2023-38408");
  script_tag(name:"creation_date", value:"2023-07-20 04:14:33 +0000 (Thu, 20 Jul 2023)");
  script_version("2023-08-02T05:06:27+0000");
  script_tag(name:"last_modification", value:"2023-08-02 05:06:27 +0000 (Wed, 02 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:07:00 +0000 (Mon, 31 Jul 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-200-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2023-200-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.429408");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-38408");
  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-9.3p2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SSA:2023-200-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssh packages are available for Slackware 15.0 and -current to
fix a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/openssh-9.3p2-i586-1_slack15.0.txz: Upgraded.
 This update fixes a security issue:
 ssh-agent(1) in OpenSSH between and 5.5 and 9.3p1 (inclusive): remote code
 execution relating to PKCS#11 providers.
 The PKCS#11 support ssh-agent(1) could be abused to achieve remote code
 execution via a forwarded agent socket if the following conditions are met:
 * Exploitation requires the presence of specific libraries on the victim
 system.
 * Remote exploitation requires that the agent was forwarded to an
 attacker-controlled system.
 Exploitation can also be prevented by starting ssh-agent(1) with an empty
 PKCS#11/FIDO allowlist (ssh-agent -P '') or by configuring an allowlist that
 contains only specific provider libraries.
 This vulnerability was discovered and demonstrated to be exploitable by the
 Qualys Security Advisory team.
 Potentially-incompatible changes:
 * ssh-agent(8): the agent will now refuse requests to load PKCS#11 modules
 issued by remote clients by default. A flag has been added to restore the
 previous behaviour: '-Oallow-remote-pkcs11'.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'openssh' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"9.3p2-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"9.3p2-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"9.3p2-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"9.3p2-x86_64-1", rls:"SLKcurrent"))) {
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
