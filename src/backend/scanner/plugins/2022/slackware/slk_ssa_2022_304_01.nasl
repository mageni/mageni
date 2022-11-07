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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.304.01");
  script_cve_id("CVE-2022-3705");
  script_tag(name:"creation_date", value:"2022-11-01 04:46:10 +0000 (Tue, 01 Nov 2022)");
  script_version("2022-11-01T10:10:51+0000");
  script_tag(name:"last_modification", value:"2022-11-01 10:10:51 +0000 (Tue, 01 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-28 17:33:00 +0000 (Fri, 28 Oct 2022)");

  script_name("Slackware: Security Advisory (SSA:2022-304-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2022-304-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.426532");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3705");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SSA:2022-304-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New vim packages are available for Slackware 15.0 and -current to fix a
security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/vim-9.0.0814-i586-1_slack15.0.txz: Upgraded.
 A vulnerability was found in vim and classified as problematic. Affected by
 this issue is the function qf_update_buffer of the file quickfix.c of the
 component autocmd Handler. The manipulation leads to use after free. The
 attack may be launched remotely. Upgrading to version 9.0.0805 is able to
 address this issue.
 Thanks to marav for the heads-up.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/vim-gvim-9.0.0814-i586-1_slack15.0.txz: Upgraded.
+--------------------------+");

  script_tag(name:"affected", value:"'vim' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"vim", ver:"9.0.0814-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"vim", ver:"9.0.0814-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"vim-gvim", ver:"9.0.0814-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"vim-gvim", ver:"9.0.0814-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"vim", ver:"9.0.0814-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"vim", ver:"9.0.0814-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"vim-gvim", ver:"9.0.0814-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"vim-gvim", ver:"9.0.0814-x86_64-1", rls:"SLKcurrent"))) {
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
