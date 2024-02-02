# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.359.01");
  script_cve_id("CVE-2023-46862", "CVE-2023-6121");
  script_tag(name:"creation_date", value:"2023-12-26 04:20:12 +0000 (Tue, 26 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 01:57:10 +0000 (Wed, 08 Nov 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-359-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2023-359-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.649908");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-46862");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-6121");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2023-359-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 15.0 to fix bugs and security
issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/linux-5.15.145/*: Upgraded.
 These updates fix various bugs and security issues.
 Thanks to jwoithe for the PCI fix!
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 Fixed in 5.15.140:
 [link moved to references]
 Fixed in 5.15.141:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kernel' package(s) on Slackware 15.0.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.145-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.145-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"5.15.145_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.145-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.145_smp-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.145-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.145-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"5.15.145_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.145-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.145-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"5.15.145_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.145-noarch-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.145_smp-noarch-1", rls:"SLK15.0"))) {
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
