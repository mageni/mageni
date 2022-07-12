###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for rdesktop RHSA-2011:0506-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00010.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870434");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-05-17 15:58:48 +0200 (Tue, 17 May 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-1595");
  script_name("RedHat Update for rdesktop RHSA-2011:0506-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rdesktop'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"rdesktop on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"rdesktop is a client for the Remote Desktop Server (previously, Terminal
  Server) in Microsoft Windows. It uses the Remote Desktop Protocol (RDP) to
  remotely present a user's desktop.

  A directory traversal flaw was found in the way rdesktop shared a local
  path with a remote server. If a user connects to a malicious server with
  rdesktop, the server could use this flaw to cause rdesktop to read and
  write to arbitrary, local files accessible to the user running rdesktop.
  (CVE-2011-1595)

  Red Hat would like to thank Cendio AB for reporting this issue. Cendio AB
  acknowledges an anonymous contributor working with the SecuriTeam Secure
  Disclosure program as the original reporter.

  Users of rdesktop should upgrade to this updated package, which contains a
  backported patch to resolve this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"rdesktop", rpm:"rdesktop~1.6.0~3.el5_6.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rdesktop-debuginfo", rpm:"rdesktop-debuginfo~1.6.0~3.el5_6.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
