###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_2757_389-ds-base_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for 389-ds-base CESA-2018:2757 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882954");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-03 17:02:18 +0530 (Wed, 03 Oct 2018)");
  script_cve_id("CVE-2018-10850", "CVE-2018-10935", "CVE-2018-14624", "CVE-2018-14638");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for 389-ds-base CESA-2018:2757 centos7");
  script_tag(name:"summary", value:"Check the version of 389-ds-base");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"389 Directory Server is an LDAP version 3
  (LDAPv3) compliant server. The base packages include the Lightweight Directory
  Access Protocol (LDAP) server and command-line utilities for server administration.

Security Fix(es):

  * 389-ds-base: race condition on reference counter leads to DoS using
persistent search (CVE-2018-10850)

  * 389-ds-base: ldapsearch with server side sort allows users to cause a
crash (CVE-2018-10935)

  * 389-ds-base: Server crash through modify command with large DN
(CVE-2018-14624)

  * 389-ds-base: Crash in delete_passwdPolicy when persistent search
connections are terminated unexpectedly (CVE-2018-14638)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

The CVE-2018-10850 issue was discovered by Thierry Bordaz (Red Hat) and the
CVE-2018-14638 issue was discovered by Viktor Ashirov (Red Hat).

Bug Fix(es):

  * Previously, the nucn-stans framework was enabled by default in Directory
Server, but the framework is not stable. As a consequence, deadlocks and
file descriptor leaks could occur. This update changes the default value of
the nsslapd-enable-nunc-stans parameter to 'off'. As a result, Directory
Server is now stable. (BZ#1614836)

  * When a search evaluates the 'shadowAccount' entry, Directory Server adds
the shadow attributes to the entry. If the fine-grained password policy is
enabled, the 'shadowAccount' entry can contain its own 'pwdpolicysubentry'
policy attribute. Previously, to retrieve this attribute, the server
started an internal search for each 'shadowAccount' entry, which was
unnecessary because the entry was already known to the server. With this
update, Directory Server only starts internal searches if the entry is not
known. As a result, the performance of searches, such as response time and
throughput, is improved. (BZ#1615924)");
  script_tag(name:"affected", value:"389-ds-base on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-September/023042.html");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.7.5~28.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.7.5~28.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.7.5~28.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.3.7.5~28.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
