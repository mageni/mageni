###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for bind-dyndb-ldap CESA-2012:0683 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-May/018652.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881069");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:00:18 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-2134");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for bind-dyndb-ldap CESA-2012:0683 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind-dyndb-ldap'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"bind-dyndb-ldap on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The dynamic LDAP back end is a plug-in for BIND that provides back-end
  capabilities to LDAP databases. It features support for dynamic updates
  and internal caching that help to reduce the load on LDAP servers.

  A flaw was found in the way bind-dyndb-ldap handled LDAP query errors. If a
  remote attacker were able to send DNS queries to a named server that is
  configured to use bind-dyndb-ldap, they could trigger such an error with a
  DNS query leveraging bind-dyndb-ldap's insufficient escaping of the LDAP
  base DN (distinguished name). This would result in an invalid LDAP query
  that named would retry in a loop, preventing it from responding to other
  DNS queries. With this update, bind-dyndb-ldap only attempts to retry one
  time when an LDAP search returns an unexpected error. (CVE-2012-2134)

  Red Hat would like to thank Ronald van Zantvoort for reporting this issue.

  All bind-dyndb-ldap users should upgrade to this updated package, which
  contains a backported patch to correct this issue. For the update to take
  effect, the named service must be restarted.");
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

  if ((res = isrpmvuln(pkg:"bind-dyndb-ldap", rpm:"bind-dyndb-ldap~0.2.0~7.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
