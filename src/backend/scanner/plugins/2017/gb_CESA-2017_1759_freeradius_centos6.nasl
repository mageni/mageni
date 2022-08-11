###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2017_1759_freeradius_centos6.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for freeradius CESA-2017:1759 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882753");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-20 07:08:45 +0200 (Thu, 20 Jul 2017)");
  script_cve_id("CVE-2017-10978", "CVE-2017-10979", "CVE-2017-10980", "CVE-2017-10981",
                "CVE-2017-10982", "CVE-2017-10983");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for freeradius CESA-2017:1759 centos6");
  script_tag(name:"summary", value:"Check the version of freeradius");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"FreeRADIUS is a high-performance and highly
configurable free Remote Authentication Dial In User Service (RADIUS) server,
designed to allow centralized authentication and authorization for a network.

Security Fix(es):

  * An out-of-bounds write flaw was found in the way FreeRADIUS server
handled certain attributes in request packets. A remote attacker could use
this flaw to crash the FreeRADIUS server or to execute arbitrary code in
the context of the FreeRADIUS server process by sending a specially crafted
request packet. (CVE-2017-10979)

  * An out-of-bounds read and write flaw was found in the way FreeRADIUS
server handled RADIUS packets. A remote attacker could use this flaw to
crash the FreeRADIUS server by sending a specially crafted RADIUS packet.
(CVE-2017-10978)

  * Multiple memory leak flaws were found in the way FreeRADIUS server
handled decoding of DHCP packets. A remote attacker could use these flaws
to cause the FreeRADIUS server to consume an increasing amount of memory
resources over time, possibly leading to a crash due to memory exhaustion,
by sending specially crafted DHCP packets. (CVE-2017-10980, CVE-2017-10981)

  * Multiple out-of-bounds read flaws were found in the way FreeRADIUS server
handled decoding of DHCP packets. A remote attacker could use these flaws
to crash the FreeRADIUS server by sending a specially crafted DHCP request.
(CVE-2017-10982, CVE-2017-10983)

Red Hat would like to thank the FreeRADIUS project for reporting these
issues. Upstream acknowledges Guido Vranken as the original reporter of
these issues.");
  script_tag(name:"affected", value:"freeradius on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-July/022507.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~2.2.6~7.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-krb5", rpm:"freeradius-krb5~2.2.6~7.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-ldap", rpm:"freeradius-ldap~2.2.6~7.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-mysql", rpm:"freeradius-mysql~2.2.6~7.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-perl", rpm:"freeradius-perl~2.2.6~7.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-postgresql", rpm:"freeradius-postgresql~2.2.6~7.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-python", rpm:"freeradius-python~2.2.6~7.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-unixODBC", rpm:"freeradius-unixODBC~2.2.6~7.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-utils", rpm:"freeradius-utils~2.2.6~7.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
