###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_0414_389-ds-base_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for 389-ds-base CESA-2018:0414 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882851");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-14 08:30:27 +0100 (Wed, 14 Mar 2018)");
  script_cve_id("CVE-2017-15135", "CVE-2018-1054");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for 389-ds-base CESA-2018:0414 centos7");
  script_tag(name:"summary", value:"Check the version of 389-ds-base");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"389 Directory Server is an LDAP version 3
(LDAPv3) compliant server. The base packages include the Lightweight Directory
Access Protocol (LDAP) server and command-line utilities for server administration.

Security Fix(es):

  * 389-ds-base: remote Denial of Service (DoS) via search filters in
SetUnicodeStringFromUTF_8 in collate.c (CVE-2018-1054)

  * 389-ds-base: Authentication bypass due to lack of size check in
slapi_ct_memcmp function in ch_malloc.c (CVE-2017-15135)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

The CVE-2017-15135 issue was discovered by Martin Poole (Red Hat).

Bug Fix(es):

  * Previously, if an administrator configured an index for an attribute with
a specific matching rule in the 'nsMatchingRule' parameter, Directory
Server did not use the retrieved indexer. As a consequence, Directory
Server did not index the values of this attribute with the specified
matching rules, and searches with extended filters were unindexed. With
this update, Directory Server uses the retrieved indexer that processes the
specified matching rule. As a result, searches using extended filters with
a specified matching rule are now indexed. (BZ#1536343)");
  script_tag(name:"affected", value:"389-ds-base on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-March/022784.html");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.6.1~28.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.6.1~28.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.6.1~28.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.3.6.1~28.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
