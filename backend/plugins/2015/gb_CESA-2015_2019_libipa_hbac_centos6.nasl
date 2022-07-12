###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libipa_hbac CESA-2015:2019 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882323");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-11-11 06:06:42 +0100 (Wed, 11 Nov 2015)");
  script_cve_id("CVE-2015-5292");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libipa_hbac CESA-2015:2019 centos6");
  script_tag(name:"summary", value:"Check the version of libipa_hbac");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The System Security Services Daemon (SSSD) service provides a set of
daemons to manage access to remote directories and authentication
mechanisms. It also provides the Name Service Switch (NSS) and the
Pluggable Authentication Modules (PAM) interfaces toward the system, and a
pluggable back-end system to connect to multiple different account sources.

It was found that SSSD's Privilege Attribute Certificate (PAC) responder
plug-in would leak a small amount of memory on each authentication request.
A remote attacker could potentially use this flaw to exhaust all available
memory on the system by making repeated requests to a Kerberized daemon
application configured to authenticate using the PAC responder plug-in.
(CVE-2015-5292)

This update also fixes the following bugs:

  * Previously, SSSD did not correctly handle sudo rules that applied to
groups with names containing special characters, such as the '(' opening
parenthesis sign. Consequently, SSSD skipped such sudo rules. The internal
sysdb search has been modified to escape special characters when searching
for objects to which sudo rules apply. As a result, SSSD applies the
described sudo rules as expected. (BZ#1258398)

  * Prior to this update, SSSD did not correctly handle group names
containing special Lightweight Directory Access Protocol (LDAP) characters,
such as the '(' or ')' parenthesis signs. When a group name contained one
or more such characters, the internal cache cleanup operation failed with
an I/O error. With this update, LDAP special characters in the
Distinguished Name (DN) of a cache entry are escaped before the cleanup
operation starts. As a result, the cleanup operation completes successfully
in the described situation. (BZ#1264098)

  * Applications performing Kerberos authentication previously increased the
memory footprint of the Kerberos plug-in that parses the Privilege
Attribute Certificate (PAC) information. The plug-in has been updated to
free the memory it allocates, thus fixing this bug. (BZ#1268783)

  * Previously, when malformed POSIX attributes were defined in an Active
Directory (AD) LDAP server, SSSD unexpectedly switched to offline mode.
This update relaxes certain checks for AD POSIX attribute validity. As a
result, SSSD now works as expected even when malformed POSIX attributes are
present in AD and no longer enters offline mode in the described situation.
(BZ#1268784)

All sssd users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
update, the sssd service will be restarted automatically. Additionally, all
running applications using the PAC responder plug-in must be restarted for
the changes to take effect.");
  script_tag(name:"affected", value:"libipa_hbac on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-November/021498.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libipa_hbac-python", rpm:"libipa_hbac-python~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_nss_idmap", rpm:"libsss_nss_idmap~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_nss_idmap-python", rpm:"libsss_nss_idmap-python~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_simpleifp", rpm:"libsss_simpleifp~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-sssdconfig", rpm:"python-sssdconfig~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-common-pac", rpm:"sssd-common-pac~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.12.4~47.el6_7.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}