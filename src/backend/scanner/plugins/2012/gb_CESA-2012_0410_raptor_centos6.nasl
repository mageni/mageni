###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for raptor CESA-2012:0410 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-March/018518.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881120");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:13:52 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-0037");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for raptor CESA-2012:0410 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'raptor'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"raptor on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Raptor provides parsers for Resource Description Framework (RDF) files.

  An XML External Entity expansion flaw was found in the way Raptor processed
  RDF files. If an application linked against Raptor were to open a
  specially-crafted RDF file, it could possibly allow a remote attacker to
  obtain a copy of an arbitrary local file that the user running the
  application had access to. A bug in the way Raptor handled external
  entities could cause that application to crash or, possibly, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2012-0037)

  Red Hat would like to thank Timothy D. Morgan of VSR for reporting this
  issue.

  All Raptor users are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. All running applications
  linked against Raptor must be restarted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"raptor", rpm:"raptor~1.4.18~5.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"raptor-devel", rpm:"raptor-devel~1.4.18~5.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
