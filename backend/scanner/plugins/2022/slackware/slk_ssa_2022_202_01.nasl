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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.202.01");
  script_cve_id("CVE-2022-24805", "CVE-2022-24806", "CVE-2022-24807", "CVE-2022-24808", "CVE-2022-24809", "CVE-2022-24810");
  script_tag(name:"creation_date", value:"2022-07-22 04:50:56 +0000 (Fri, 22 Jul 2022)");
  script_version("2022-07-22T04:50:56+0000");
  script_tag(name:"last_modification", value:"2022-07-22 04:50:56 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2022-202-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2022-202-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.414596");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the SSA:2022-202-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New net-snmp packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/net-snmp-5.9.3-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 A buffer overflow in the handling of the INDEX of NET-SNMP-VACM-MIB can cause
 an out-of-bounds memory access.
 A malformed OID in a GET-NEXT to the nsVacmAccessTable can cause a NULL
 pointer dereference.
 Improper Input Validation when SETing malformed OIDs in master agent and
 subagent simultaneously.
 A malformed OID in a SET request to SNMP-VIEW-BASED-ACM-MIB::vacmAccessTable
 can cause an out-of-bounds memory access.
 A malformed OID in a SET request to NET-SNMP-AGENT-MIB::nsLogTable can cause a
 NULL pointer dereference.
 A malformed OID in a SET to the nsVacmAccessTable can cause a NULL pointer
 dereference.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"net-snmp", ver:"5.9.3-i586-1_slack15.0", rls:"SLK15.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"net-snmp", ver:"5.9.3-x86_64-1_slack15.0", rls:"SLK15.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
