###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libproxy CESA-2012:1461 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-November/018996.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881537");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-11-15 11:42:38 +0530 (Thu, 15 Nov 2012)");
  script_cve_id("CVE-2012-4505");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for libproxy CESA-2012:1461 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libproxy'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"libproxy on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"libproxy is a library that handles all the details of proxy configuration.

  A buffer overflow flaw was found in the way libproxy handled the
  downloading of proxy auto-configuration (PAC) files. A malicious server
  hosting a PAC file or a man-in-the-middle attacker could use this flaw to
  cause an application using libproxy to crash or, possibly, execute
  arbitrary code, if the proxy settings obtained by libproxy (from the
  environment or the desktop environment settings) instructed the use of a
  PAC proxy configuration. (CVE-2012-4505)

  This issue was discovered by the Red Hat Security Response Team.

  Users of libproxy should upgrade to these updated packages, which contain
  a backported patch to correct this issue. All applications using libproxy
  must be restarted for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"libproxy", rpm:"libproxy~0.3.0~3.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-bin", rpm:"libproxy-bin~0.3.0~3.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-devel", rpm:"libproxy-devel~0.3.0~3.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-gnome", rpm:"libproxy-gnome~0.3.0~3.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-kde", rpm:"libproxy-kde~0.3.0~3.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-mozjs", rpm:"libproxy-mozjs~0.3.0~3.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-python", rpm:"libproxy-python~0.3.0~3.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-webkit", rpm:"libproxy-webkit~0.3.0~3.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
