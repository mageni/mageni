###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for slapi-nis CESA-2015:0728 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882144");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-04-01 07:23:35 +0200 (Wed, 01 Apr 2015)");
  script_cve_id("CVE-2015-0283", "CVE-2015-1827");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for slapi-nis CESA-2015:0728 centos7");
  script_tag(name:"summary", value:"Check the version of slapi-nis");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Red Hat Identity Management is a centralized authentication, identity
management, and authorization solution for both traditional and cloud-based
enterprise environments. It integrates components of the Red Hat Directory
Server, MIT Kerberos, Red Hat Certificate System, NTP, and DNS. It provides
web browser and command-line interfaces. Its administration tools allow an
administrator to quickly install, set up, and administer a group of domain
controllers to meet the authentication and identity management requirements
of large-scale Linux and UNIX deployments.

The ipa component provides centrally managed Identity, Policy, and Audit.
The slapi-nis component provides NIS Server and Schema Compatibility
plug-ins for Directory Server.

It was discovered that the IPA extdom Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for a list of groups for a user that belongs to a
large number of groups would cause a Directory Server to crash.
(CVE-2015-1827)

It was discovered that the slapi-nis Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for information about a group with many members, or
a request for a user that belongs to a large number of groups, would cause
a Directory Server to enter an infinite loop and consume an excessive
amount of CPU time. (CVE-2015-0283)

These issues were discovered by Sumit Bose of Red Hat.

This update fixes the following bugs:

  * Previously, users of IdM were not properly granted the default permission
to read the 'facsimiletelephonenumber' user attribute. This update adds
'facsimiletelephonenumber' to the Access Control Instruction (ACI) for user
data, which makes the attribute readable to authenticated users as
expected. (BZ#1198430)

  * Prior to this update, when a DNS zone was saved in an LDAP database
without a dot character (.) at the end, internal DNS commands and
operations, such as dnsrecord-* or dnszone-*, failed. With this update, DNS
commands always supply the DNS zone with a dot character at the end, which
prevents the described problem. (BZ#1198431)

  * After a full-server IdM restore operation, the restored server in some
cases contained invalid data. In addition, if the restored server was used
to reinitialize a replica, the replica then contained invalid data as well.
To fix this problem, the IdM API is now created correctly during the
restore operation, and *.ldif files are not skipped during the removal of
RUV data. As a result, the restored server and its replica no longer
contain invalid data. (BZ#1199060)

  * ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"slapi-nis on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-April/021038.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"slapi-nis", rpm:"slapi-nis~0.54~3.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}