# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.048.01");
  script_cve_id("CVE-2022-3344", "CVE-2022-3424", "CVE-2022-3534", "CVE-2022-3545", "CVE-2022-36280", "CVE-2022-3643", "CVE-2022-41218", "CVE-2022-4129", "CVE-2022-4378", "CVE-2022-4382", "CVE-2022-45869", "CVE-2022-45934", "CVE-2022-47518", "CVE-2022-47519", "CVE-2022-47520", "CVE-2022-47521", "CVE-2022-47929", "CVE-2022-4842", "CVE-2023-0045", "CVE-2023-0179", "CVE-2023-0210", "CVE-2023-0266", "CVE-2023-0394", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-23559");
  script_tag(name:"creation_date", value:"2023-02-20 04:18:41 +0000 (Mon, 20 Feb 2023)");
  script_version("2023-02-20T10:17:05+0000");
  script_tag(name:"last_modification", value:"2023-02-20 10:17:05 +0000 (Mon, 20 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 15:27:00 +0000 (Mon, 12 Dec 2022)");

  script_name("Slackware: Security Advisory (SSA:2023-048-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2023-048-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.743608");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3344");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3424");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3534");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3545");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-36280");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3643");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-41218");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-4129");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-4378");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-4382");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45869");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45934");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-47518");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-47519");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-47520");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-47521");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-47929");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-4842");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-0045");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-0179");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-0210");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-0266");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-0394");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23454");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23455");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23559");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2023-048-01 advisory.");

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
 Fixed in 5.15.81:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.82:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.83:
 [link moved to references]
 Fixed in 5.15.84:
 [link moved to references]
 Fixed in 5.15.85:
 [link moved to references]
 Fixed in 5.15.86:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.87:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.88:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.89:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.90:
 [link moved to references]
 [link moved to references]
 Fixed in 5.15.91:
 [link moved to references]
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

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.94-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.94-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"5.15.94_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.94-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.94_smp-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.94-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.94-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"5.15.94_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.94-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.94-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"5.15.94_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.94-noarch-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.94_smp-noarch-1", rls:"SLK15.0"))) {
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
