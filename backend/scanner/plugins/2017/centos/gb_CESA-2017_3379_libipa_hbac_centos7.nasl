###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2017_3379_libipa_hbac_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for libipa_hbac CESA-2017:3379 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882813");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-12-07 07:39:34 +0100 (Thu, 07 Dec 2017)");
  script_cve_id("CVE-2017-12173");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libipa_hbac CESA-2017:3379 centos7");
  script_tag(name:"summary", value:"Check the version of libipa_hbac");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The System Security Services Daemon (SSSD)
service provides a set of daemons to manage access to remote directories and
authentication mechanisms. It also provides the Name Service Switch (NSS) and
the Pluggable Authentication Modules (PAM) interfaces toward the system, and a
pluggable back-end system to connect to multiple different account sources.

Security Fix(es):

  * It was found that sssd's sysdb_search_user_by_upn_res() function did not
sanitize requests when querying its local cache and was vulnerable to
injection. In a centralized login environment, if a password hash was
locally cached for a given user, an authenticated attacker could use this
flaw to retrieve it. (CVE-2017-12173)

This issue was discovered by Sumit Bose (Red Hat).

Bug Fix(es):

  * Previously, SSSD's krb5 provider did not respect changed UIDs in ID views
overriding the default view. Consequently, Kerberos credential caches were
created with the incorrect, original UID, and processes of the user were
not able to find the changed UID. With this update, SSSD's krb5 provider is
made aware of the proper ID view name and respects the ID override data. As
a result, the Kerberos credential cache is now created with the expected
UID, and the processes can find it. (BZ#1508972)

  * Previously, the list of cache request domains was sometimes freed in the
middle of a cache request operation due to the refresh domains request, as
they both were using the same list. As a consequence, a segmentation fault
sometimes occurred in SSSD. With this update, SSSD uses a copy of the cache
request domains' list for each cache request. As a result, SSSD no longer
crashes in this case. (BZ#1509177)

  * Previously, the calls provided by SSSD to send data to the Privilege
Attribute Certificate (PAC) responder did not use a mutex or any other
means to serialize access to the PAC responder from a single process. When
multithreaded applications overran the PAC responder with multiple parallel
requests, some threads did not receive a proper reply. Consequently, such
threads only resumed work after waiting 5 minutes for a response. This
update configures mutex to serialize access to the PAC responder socket for
multithreaded applications. As a result, all threads now get a proper and
timely reply. (BZ#1506682)");
  script_tag(name:"affected", value:"libipa_hbac on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-December/022685.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_autofs", rpm:"libsss_autofs~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_certmap", rpm:"libsss_certmap~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_certmap-devel", rpm:"libsss_certmap-devel~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_nss_idmap", rpm:"libsss_nss_idmap~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_simpleifp", rpm:"libsss_simpleifp~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_sudo", rpm:"libsss_sudo~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libipa_hbac", rpm:"python-libipa_hbac~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libsss_nss_idmap", rpm:"python-libsss_nss_idmap~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-sss", rpm:"python-sss~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-sssdconfig", rpm:"python-sssdconfig~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-sss-murmur", rpm:"python-sss-murmur~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-common-pac", rpm:"sssd-common-pac~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-kcm", rpm:"sssd-kcm~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-libwbclient", rpm:"sssd-libwbclient~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-libwbclient-devel", rpm:"sssd-libwbclient-devel~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-polkit-rules", rpm:"sssd-polkit-rules~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-winbind-idmap", rpm:"sssd-winbind-idmap~1.15.2~50.el7_4.8", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
