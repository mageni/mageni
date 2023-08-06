# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.205.01");
  script_cve_id("CVE-2023-20593");
  script_tag(name:"creation_date", value:"2023-07-25 08:39:33 +0000 (Tue, 25 Jul 2023)");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 19:29:00 +0000 (Tue, 01 Aug 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-205-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.2|15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2023-205-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.436965");
  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2023/q3/59");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-20593");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SSA:2023-205-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel-firmware packages are available for Slackware 14.2, 15.0,
and -current to fix a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/kernel-firmware-20230724_59fbffa-noarch-1.txz: Upgraded.
 AMD microcode updated to fix a use-after-free in AMD Zen2 processors.
 From Tavis Ormandy's annoucement of the issue:
 'The practical result here is that you can spy on the registers of other
 processes. No system calls or privileges are required.
 It works across virtual machines and affects all operating systems.
 I have written a poc for this issue that's fast enough to reconstruct
 keys and passwords as users log in.'
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on Slackware 14.2, Slackware 15.0, Slackware current.");

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

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"20230724_59fbffa-noarch-1", rls:"SLK14.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"20230724_59fbffa-noarch-1", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"20230724_59fbffa-noarch-1", rls:"SLKcurrent"))) {
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
