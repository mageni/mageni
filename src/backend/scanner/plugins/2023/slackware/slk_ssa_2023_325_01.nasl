# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.325.01");
  script_cve_id("CVE-2022-40982", "CVE-2022-45886", "CVE-2022-45887", "CVE-2022-45919", "CVE-2022-48502", "CVE-2023-1206", "CVE-2023-20569", "CVE-2023-20588", "CVE-2023-20593", "CVE-2023-2124", "CVE-2023-2898", "CVE-2023-31085", "CVE-2023-3117", "CVE-2023-31248", "CVE-2023-3212", "CVE-2023-3338", "CVE-2023-3390", "CVE-2023-34255", "CVE-2023-34324", "CVE-2023-35001", "CVE-2023-35788", "CVE-2023-35827", "CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3772", "CVE-2023-3776", "CVE-2023-3777", "CVE-2023-38432", "CVE-2023-3863", "CVE-2023-3865", "CVE-2023-3866", "CVE-2023-39189", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-4004", "CVE-2023-4015", "CVE-2023-40283", "CVE-2023-4128", "CVE-2023-4132", "CVE-2023-4147", "CVE-2023-4206", "CVE-2023-4207", "CVE-2023-4208", "CVE-2023-4244", "CVE-2023-4273", "CVE-2023-42752", "CVE-2023-42753", "CVE-2023-42754", "CVE-2023-42755", "CVE-2023-44466", "CVE-2023-4563", "CVE-2023-4569", "CVE-2023-45871", "CVE-2023-4623", "CVE-2023-46813", "CVE-2023-4881", "CVE-2023-4921", "CVE-2023-5158", "CVE-2023-5178", "CVE-2023-5197", "CVE-2023-5717");
  script_tag(name:"creation_date", value:"2023-11-22 04:19:47 +0000 (Wed, 22 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-15 17:15:08 +0000 (Mon, 15 Jan 2024)");

  script_name("Slackware: Security Advisory (SSA:2023-325-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2023-325-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.892863");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-40982");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45886");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45887");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45919");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-48502");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1206");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-20569");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-20588");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-20593");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2124");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-2898");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3117");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-31248");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3212");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3338");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3390");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-34255");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-35001");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-35788");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3609");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3610");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3611");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3772");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3776");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3777");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-38432");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3863");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3865");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-3866");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-39194");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4004");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4015");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-40283");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4128");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4132");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4147");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4206");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4207");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4208");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4273");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-44466");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4569");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2023-325-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 15.0 to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/linux-5.15.139/*: Upgraded.
 These updates fix various bugs and security issues.
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 Fixed in 5.15.116:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.117:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.118:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.119:
 [link moved to references]
 Fixed in 5.15.121:
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
 [link moved to references]
 Fixed in 5.15.122:
 [link moved to references]
 Fixed in 5.15.123:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.124:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.125:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.126:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.128:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.132:
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

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.139-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.139-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"5.15.139_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.139-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.139_smp-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.139-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.139-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"5.15.139_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.139-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.139-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"5.15.139_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.139-noarch-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.139_smp-noarch-1", rls:"SLK15.0"))) {
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
