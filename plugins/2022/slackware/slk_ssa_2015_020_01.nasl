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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2015.020.01");
  script_cve_id("CVE-2014-8143");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2015-020-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK14\.1");

  script_xref(name:"Advisory-ID", value:"SSA:2015-020-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2015&m=slackware-security.416326");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SSA:2015-020-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New samba packages are available for Slackware 14.1 and -current to
fix a security issue.


Here are the details from the Slackware 14.1 ChangeLog:
+--------------------------+
patches/packages/samba-4.1.16-i486-1_slack14.1.txz: Upgraded.
 This update is a security release in order to address CVE-2014-8143
 (Elevation of privilege to Active Directory Domain Controller).
 Samba's AD DC allows the administrator to delegate creation of user or
 computer accounts to specific users or groups. However, all released
 versions of Samba's AD DC did not implement the additional required
 check on the UF_SERVER_TRUST_ACCOUNT bit in the userAccountControl
 attributes. Most Samba deployments are not of the AD Domain Controller,
 but are of the classic domain controller, the file server or print server.
 Only the Active Directory Domain Controller is affected by this issue.
 Additionally, most sites running the AD Domain Controller do not configure
 delegation for the creation of user or computer accounts, and so are not
 vulnerable to this issue, as no writes are permitted to the
 userAccountControl attribute, no matter what the value.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'samba' package(s) on Slackware 14.1, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.1.16-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.1.16-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
