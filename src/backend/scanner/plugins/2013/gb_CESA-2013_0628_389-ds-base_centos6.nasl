###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for 389-ds-base CESA-2013:0628 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019641.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881683");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-15 09:51:36 +0530 (Fri, 15 Mar 2013)");
  script_cve_id("CVE-2013-0312");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for 389-ds-base CESA-2013:0628 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"389-ds-base on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The 389 Directory Server is an LDAPv3 compliant server. The base packages
  include the Lightweight Directory Access Protocol (LDAP) server and
  command-line utilities for server administration.

  A flaw was found in the way LDAPv3 control data was handled by 389
  Directory Server. If a malicious user were able to bind to the directory
  (even anonymously) and send an LDAP request containing crafted LDAPv3
  control data, they could cause the server to crash, denying service to the
  directory. (CVE-2013-0312)

  The CVE-2013-0312 issue was discovered by Thierry Bordaz of Red Hat.

  This update also fixes the following bugs:

  * After an upgrade from Red Hat Enterprise Linux 6.3 to version 6.4, the
  upgrade script did not update the schema file for the PamConfig object
  class. Consequently, new features for PAM such as configuration of multiple
  instances and pamFilter attribute could not be used because of the schema
  violation. With this update, the upgrade script updates the schema file for
  the PamConfig object class and new features function properly. (BZ#910994)

  * Previously, the valgrind test suite reported recurring memory leaks in
  the modify_update_last_modified_attr() function. The size of the leaks
  averaged between 60-80 bytes per modify call. In environments where modify
  operations were frequent, this caused significant problems. Now, memory
  leaks no longer occur in the modify_update_last_modified_attr() function.
  (BZ#910995)

  * The Directory Server (DS) failed when multi-valued attributes were
  replaced. The problem occurred when replication was enabled, while the
  server executing the modification was configured as a single master and
  there was at least one replication agreement. Consequently, the
  modification requests were refused by the master server, which returned a
  code 20 'Type or value exists' error message. These requests were
  replacements of multi-valued attributes, and the error only occurred when
  one of the new values matched one of the current values of the attribute,
  but had a different letter case. Now, modification requests function
  properly and no longer return code 20 errors. (BZ#910996)

  * The DNA (distributed numeric assignment) plug-in, under certain
  conditions, could log error messages with the 'DB_LOCK_DEADLOCK' error
  code when attempting to create an entry with a uidNumber attribute. Now,
  DNA handles this case properly and errors no longer occur during attempts
  to create entries with uidNumber attributes. (BZ#911467)

  * Posix Winsync plugin was calling an internal mo ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~12.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.2.11.15~12.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~12.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
