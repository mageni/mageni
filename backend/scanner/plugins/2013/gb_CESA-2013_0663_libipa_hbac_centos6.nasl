###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libipa_hbac CESA-2013:0663 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019657.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881693");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-22 10:40:33 +0530 (Fri, 22 Mar 2013)");
  script_cve_id("CVE-2013-0287");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_name("CentOS Update for libipa_hbac CESA-2013:0663 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libipa_hbac'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"libipa_hbac on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"SSSD (System Security Services Daemon) provides a set of daemons to manage
  access to remote directories and authentication mechanisms. It provides
  NSS (Name Service Switch) and PAM (Pluggable Authentication Modules)
  interfaces toward the system and a pluggable back end system to connect to
  multiple different account sources.

  When SSSD was configured as a Microsoft Active Directory client by using
  the new Active Directory provider (introduced in RHSA-2013:0508), the
  Simple Access Provider ('access_provider = simple in
  /etc/sssd/sssd.conf') did not handle access control correctly. If any
  groups were specified with the simple_deny_groups option (in sssd.conf),
  all users were permitted access. (CVE-2013-0287)

  The CVE-2013-0287 issue was discovered by Kaushik Banerjee of Red Hat.

  This update also fixes the following bugs:

  * If a group contained a member whose Distinguished Name (DN) pointed out
  of any of the configured search bases, the search request that was
  processing this particular group never ran to completion. To the user, this
  bug manifested as a long timeout between requesting the group data and
  receiving the result. A patch has been provided to address this bug and
  SSSD now processes group search requests without delays. (BZ#907362)

  * The pwd_expiration_warning should have been set for seven days, but
  instead it was set to zero for Kerberos. This incorrect zero setting
  returned the 'always display warning if the server sends one' error message
  and users experienced problems in environments like IPA or Active
  Directory. Currently, the value setting for Kerberos is modified and this
  issue no longer occurs. (BZ#914671)

  All users of sssd are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libipa_hbac-python", rpm:"libipa_hbac-python~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_autofs", rpm:"libsss_autofs~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_sudo", rpm:"libsss_sudo~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_sudo-devel", rpm:"libsss_sudo-devel~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.9.2~82.4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
