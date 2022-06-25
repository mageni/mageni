###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openldap CESA-2014:0126 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881872");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-11 10:30:42 +0530 (Tue, 11 Feb 2014)");
  script_cve_id("CVE-2013-4449");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for openldap CESA-2014:0126 centos6");

  script_tag(name:"affected", value:"openldap on CentOS 6");
  script_tag(name:"insight", value:"OpenLDAP is an open source suite of Lightweight Directory Access Protocol
(LDAP) applications and development tools. LDAP is a set of protocols used
to access and maintain distributed directory information services over an
IP network. The openldap package contains configuration files, libraries,
and documentation for OpenLDAP.

A denial of service flaw was found in the way the OpenLDAP server daemon
(slapd) performed reference counting when using the rwm (rewrite/remap)
overlay. A remote attacker able to query the OpenLDAP server could use this
flaw to crash the server by immediately unbinding from the server after
sending a search request. (CVE-2013-4449)

Red Hat would like to thank Michael Vishchers from Seven Principles AG for
reporting this issue.

This update also fixes the following bug:

  * Previously, OpenLDAP did not properly handle a number of simultaneous
updates. As a consequence, sending a number of parallel update requests to
the server could cause a deadlock. With this update, a superfluous locking
mechanism causing the deadlock has been removed, thus fixing the bug.
(BZ#1056124)

All openldap users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-February/020132.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.23~34.el6_5.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.23~34.el6_5.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.4.23~34.el6_5.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.23~34.el6_5.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.4.23~34.el6_5.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
