# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.333.01");
  script_cve_id("CVE-2022-0171", "CVE-2022-20421", "CVE-2022-2308", "CVE-2022-2602", "CVE-2022-2663", "CVE-2022-2905", "CVE-2022-2978", "CVE-2022-3028", "CVE-2022-3061", "CVE-2022-3169", "CVE-2022-3176", "CVE-2022-3303", "CVE-2022-3521", "CVE-2022-3524", "CVE-2022-3535", "CVE-2022-3542", "CVE-2022-3543", "CVE-2022-3564", "CVE-2022-3565", "CVE-2022-3586", "CVE-2022-3594", "CVE-2022-3619", "CVE-2022-3621", "CVE-2022-3623", "CVE-2022-3625", "CVE-2022-3628", "CVE-2022-3629", "CVE-2022-3633", "CVE-2022-3635", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-39190", "CVE-2022-39842", "CVE-2022-40307", "CVE-2022-40768", "CVE-2022-4095", "CVE-2022-41674", "CVE-2022-41849", "CVE-2022-41850", "CVE-2022-42703", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721", "CVE-2022-42722", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-43750", "CVE-2022-43945");
  script_tag(name:"creation_date", value:"2022-11-30 04:18:51 +0000 (Wed, 30 Nov 2022)");
  script_version("2022-11-30T10:12:07+0000");
  script_tag(name:"last_modification", value:"2022-11-30 10:12:07 +0000 (Wed, 30 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-25 14:45:00 +0000 (Tue, 25 Oct 2022)");

  script_name("Slackware: Security Advisory (SSA:2022-333-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2022-333-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.829022");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-0171");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-20421");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-2308");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-2602");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-2663");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-2905");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-2978");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3028");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3061");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3176");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3303");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3524");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3535");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3542");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3565");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3586");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3594");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3621");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3623");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3625");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3628");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3629");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3633");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3635");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3646");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3649");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-39190");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-39842");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-40307");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-40768");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-4095");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-41674");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-41849");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-41850");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-42703");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-42719");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-42720");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-42721");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-42722");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-42896");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-43750");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-43945");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2022-333-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 15.0 to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/linux-5.15.80/*: Upgraded.
 These updates fix various bugs and security issues.
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 Fixed in 5.15.63:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.64:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.65:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.66:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.68:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.70:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.72:
 [link moved to references]
 Fixed in 5.15.73:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.74:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.75:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.77:
 [link moved to references]
 Fixed in 5.15.78:
 [link moved to references]
 [link moved to references]
 [link moved to references]
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

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.80-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.80-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"5.15.80_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.80-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.80_smp-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.80-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.80-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"5.15.80_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.80-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.80-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"5.15.80_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.80-noarch-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.80_smp-noarch-1", rls:"SLK15.0"))) {
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
