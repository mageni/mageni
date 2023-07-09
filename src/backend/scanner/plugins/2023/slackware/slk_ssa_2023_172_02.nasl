# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.172.02");
  script_cve_id("CVE-2022-2196", "CVE-2022-27672", "CVE-2022-3707", "CVE-2022-4269", "CVE-2022-4379", "CVE-2022-48425", "CVE-2023-0459", "CVE-2023-1076", "CVE-2023-1077", "CVE-2023-1078", "CVE-2023-1079", "CVE-2023-1118", "CVE-2023-1281", "CVE-2023-1380", "CVE-2023-1513", "CVE-2023-1611", "CVE-2023-1670", "CVE-2023-1829", "CVE-2023-1855", "CVE-2023-1859", "CVE-2023-1989", "CVE-2023-1990", "CVE-2023-2002", "CVE-2023-2156", "CVE-2023-2162", "CVE-2023-2194", "CVE-2023-2235", "CVE-2023-2248", "CVE-2023-2269", "CVE-2023-23004", "CVE-2023-2483", "CVE-2023-25012", "CVE-2023-26545", "CVE-2023-28466", "CVE-2023-2985", "CVE-2023-30456", "CVE-2023-30772", "CVE-2023-31436", "CVE-2023-32233", "CVE-2023-32269", "CVE-2023-33203", "CVE-2023-33288", "CVE-2023-34256");
  script_tag(name:"creation_date", value:"2023-06-22 04:16:37 +0000 (Thu, 22 Jun 2023)");
  script_version("2023-06-22T10:34:14+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:14 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 14:12:00 +0000 (Fri, 13 Jan 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-172-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2023-172-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.816190");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-2196");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-27672");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3707");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-4269");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-4379");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-0459");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1076");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1077");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1078");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1079");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1118");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1281");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1380");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1513");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1611");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1670");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1829");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1855");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1859");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1989");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1990");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2002");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2156");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2162");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2194");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2235");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2248");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2269");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23004");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2483");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-25012");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-26545");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-28466");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2985");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-30456");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-30772");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-31436");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-32233");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-32269");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-33203");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-33288");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2023-172-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 15.0 to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/linux-5.15.118/*: Upgraded.
 These updates fix various bugs and security issues.
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 Fixed in 5.15.93:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.94:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.95:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.96:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.99:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.100:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.104:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.105:
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
 Fixed in 5.15.106:
 [link moved to references]
 Fixed in 5.15.108:
 [link moved to references]
 Fixed in 5.15.109:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.110:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.111:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.112:
 ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.118-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.118-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"5.15.118_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.118-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.118_smp-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.118-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.118-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"5.15.118_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.118-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.118-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"5.15.118_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.118-noarch-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.118_smp-noarch-1", rls:"SLK15.0"))) {
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
