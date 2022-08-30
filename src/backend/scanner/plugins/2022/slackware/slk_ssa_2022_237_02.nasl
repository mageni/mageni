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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.237.02");
  script_cve_id("CVE-2021-33655", "CVE-2022-1012", "CVE-2022-1184", "CVE-2022-1462", "CVE-2022-1652", "CVE-2022-1679", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1789", "CVE-2022-1852", "CVE-2022-1943", "CVE-2022-1966", "CVE-2022-1972", "CVE-2022-1973", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-2078", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-21499", "CVE-2022-21505", "CVE-2022-2318", "CVE-2022-2503", "CVE-2022-2585", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-26365", "CVE-2022-26373", "CVE-2022-2873", "CVE-2022-28893", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-32250", "CVE-2022-32296", "CVE-2022-32981", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33743", "CVE-2022-33744", "CVE-2022-34494", "CVE-2022-34495", "CVE-2022-34918", "CVE-2022-36123", "CVE-2022-36879", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-08-26 05:09:05 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T05:09:05+0000");
  script_tag(name:"last_modification", value:"2022-08-26 05:09:05 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 13:36:00 +0000 (Thu, 11 Aug 2022)");

  script_name("Slackware: Security Advisory (SSA:2022-237-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2022-237-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.885651");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2022-237-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 15.0 to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/linux-5.15.63/*: Upgraded.
 These updates fix various bugs and security issues.
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 Fixed in 5.15.39:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.40:
 [link moved to references]
 Fixed in 5.15.41:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.42:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.44:
 [link moved to references]
 Fixed in 5.15.45:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.46:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.47:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.48:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.53:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.54:
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

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.63-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.63-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"5.15.63_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.63-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.63_smp-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.63-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.63-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"5.15.63_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.63-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.63-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"5.15.63_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.63-noarch-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.63_smp-noarch-1", rls:"SLK15.0"))) {
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
