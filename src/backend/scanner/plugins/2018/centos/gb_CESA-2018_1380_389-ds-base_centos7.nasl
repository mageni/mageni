###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_1380_389-ds-base_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for 389-ds-base CESA-2018:1380 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882899");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-06-05 14:03:25 +0530 (Tue, 05 Jun 2018)");
  script_cve_id("CVE-2018-1089");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for 389-ds-base CESA-2018:1380 centos7");
  script_tag(name:"summary", value:"Check the version of 389-ds-base");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"389 Directory Server is an LDAP version 3 (LDAPv3) compliant server. The
base packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

Security Fix(es):

  * 389-ds-base: ns-slapd crash via large filter value in ldapsearch
(CVE-2018-1089)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Greg Kubok for reporting this issue.

Bug Fix(es):

  * Indexing tasks in Directory Server contain the nsTaskStatus attribute to
monitor whether the task is completed and the database is ready to receive
updates. Before this update, the server set the value that indexing had
completed before the database was ready to receive updates. Applications
which monitor nsTaskStatus could start sending updates as soon as indexing
completed, but before the database was ready. As a consequence, the server
rejected updates with an UNWILLING_TO_PERFORM error. The problem has been
fixed. As a result, the nsTaskStatus attribute now shows that indexing is
completed after the database is ready to receive updates. (BZ#1553605)

  * Previously, Directory Server did not remember when the first operation,
bind, or a connection was started. As a consequence, the server applied in
certain situations anonymous resource limits to an authenticated client.
With this update, Directory Server properly marks authenticated client
connections. As a result, it applies the correct resource limits, and
authenticated clients no longer get randomly restricted by anonymous
resource limits. (BZ#1554720)

  * When debug replication logging is enabled, Directory Server incorrectly
logged an error that updating the replica update vector (RUV) failed when
in fact the update succeeded. The problem has been fixed, and the server no
longer logs an error if updating the RUV succeeds. (BZ#1559464)

  * This update adds the -W option to the ds-replcheck utility. With this
option, ds-replcheck asks for the password, similar to OpenLDAP utilities.
As a result, the password is not stored in the shell's history file when
the -W option is used. (BZ#1559760)

  * If an administrator moves a group in Directory Server from one subtree to
another, the memberOf plug-in deletes the memberOf attribute with the old
value and adds a new memberOf attribute with the new group's distinguished
name (DN) in affected user entries. Previously, if the old subtree was not
within the scope of the memberOf plug-in, deleting the old memberOf
attribute failed because the values ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"389-ds-base on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-May/022850.html");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.7.5~21.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.7.5~21.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.7.5~21.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.3.7.5~21.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}