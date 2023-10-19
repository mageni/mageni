# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.284.03");
  script_cve_id("CVE-2023-3961", "CVE-2023-4091", "CVE-2023-4154", "CVE-2023-42669", "CVE-2023-42670");
  script_tag(name:"creation_date", value:"2023-10-12 04:17:23 +0000 (Thu, 12 Oct 2023)");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2023-284-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2023-284-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.440518");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3961");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4091");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4154");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-42669");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-42670");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-3961.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-4091.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-4154.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-42669.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-42670.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SSA:2023-284-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New samba packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/samba-4.18.8-i586-1_slack15.0.txz: Upgraded.
 This is a security release in order to address the following defects:
 Unsanitized pipe names allow SMB clients to connect as root to existing
 unix domain sockets on the file system.
 SMB client can truncate files to 0 bytes by opening files with OVERWRITE
 disposition when using the acl_xattr Samba VFS module with the smb.conf
 setting 'acl_xattr:ignore system acls = yes'
 An RODC and a user with the GET_CHANGES right can view all attributes,
 including secrets and passwords. Additionally, the access check fails
 open on error conditions.
 Calls to the rpcecho server on the AD DC can request that the server block
 for a user-defined amount of time, denying service.
 Samba can be made to start multiple incompatible RPC listeners, disrupting
 service on the AD DC.
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

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.18.8-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.18.8-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.19.1-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.19.1-x86_64-1", rls:"SLKcurrent"))) {
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
