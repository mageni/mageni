###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_1060_pcs_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for pcs CESA-2018:1060 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882895");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-06-05 14:03:24 +0530 (Tue, 05 Jun 2018)");
  script_cve_id("CVE-2018-1079", "CVE-2018-1086", "CVE-2018-1000119");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for pcs CESA-2018:1060 centos7");
  script_tag(name:"summary", value:"Check the version of pcs");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The pcs packages provide a command-line configuration system for the
Pacemaker and Corosync utilities.

Security Fix(es):

  * pcs: Privilege escalation via authorized user malicious REST call
(CVE-2018-1079)

  * pcs: Debug parameter removal bypass, allowing information disclosure
(CVE-2018-1086)

  * rack-protection: Timing attack in authenticity_token.rb
(CVE-2018-1000119)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

The CVE-2018-1079 issue was discovered by Ondrej Mular (Red Hat) and the
CVE-2018-1086 issue was discovered by Cedric Buissart (Red Hat).");
  script_tag(name:"affected", value:"pcs on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-May/022893.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"pcs", rpm:"pcs~0.9.162~5.el7.centos.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcs-snmp", rpm:"pcs-snmp~0.9.162~5.el7.centos.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}