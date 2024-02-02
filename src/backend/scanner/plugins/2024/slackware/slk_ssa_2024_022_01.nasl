# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.022.01");
  script_tag(name:"creation_date", value:"2024-01-23 04:20:11 +0000 (Tue, 23 Jan 2024)");
  script_version("2024-01-23T05:05:19+0000");
  script_tag(name:"last_modification", value:"2024-01-23 05:05:19 +0000 (Tue, 23 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2024-022-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2024-022-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.396188");
  script_xref(name:"URL", value:"https://www.postfix.org/smtp-smuggling.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postfix' package(s) announced via the SSA:2024-022-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New postfix packages are available for Slackware 15.0 and -current to
fix a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/postfix-3.6.14-i586-1_slack15.0.txz: Upgraded.
 Security (inbound SMTP smuggling): with 'smtpd_forbid_bare_newline
 = normalize' (default 'no' for Postfix < 3.9), the Postfix
 SMTP server requires the standard End-of-DATA sequence
 <CR><LF>.<CR><LF>, and otherwise allows command or message
 content lines ending in the non-standard <LF>, processing
 them as if the client sent the standard <CR><LF>.
 The alternative setting, 'smtpd_forbid_bare_newline = reject'
 will reject any command or message that contains a bare
 <LF>, and is more likely to cause problems with legitimate
 clients.
 For backwards compatibility, local clients are excluded by
 default with 'smtpd_forbid_bare_newline_exclusions =
 $mynetworks'.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'postfix' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"postfix", ver:"3.6.14-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"postfix", ver:"3.6.14-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"postfix", ver:"3.8.5-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"postfix", ver:"3.8.5-x86_64-1", rls:"SLKcurrent"))) {
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
