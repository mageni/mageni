###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for curl CESA-2014:0561 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.881936");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-06-02 13:43:01 +0530 (Mon, 02 Jun 2014)");
  script_cve_id("CVE-2014-0015", "CVE-2014-0138");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("CentOS Update for curl CESA-2014:0561 centos6");

  script_tag(name:"affected", value:"curl on CentOS 6");
  script_tag(name:"insight", value:"cURL provides the libcurl library and a command line tool
for downloading files from servers using various protocols, including HTTP,
FTP, and LDAP.

It was found that libcurl could incorrectly reuse existing connections for
requests that should have used different or no authentication credentials,
when using one of the following protocols: HTTP(S) with NTLM
authentication, LDAP(S), SCP, or SFTP. If an application using the libcurl
library connected to a remote server with certain authentication
credentials, this flaw could cause other requests to use those same
credentials. (CVE-2014-0015, CVE-2014-0138)

Red Hat would like to thank the cURL project for reporting these issues.
Upstream acknowledges Paras Sethia as the original reporter of
CVE-2014-0015 and Yehezkel Horowitz for discovering the security impact of
this issue, and Steve Holme as the original reporter of CVE-2014-0138.

This update also fixes the following bugs:

  * Previously, the libcurl library was closing a network socket without
first terminating the SSL connection using the socket. This resulted in a
write after close and consequent leakage of memory dynamically allocated by
the SSL library. An upstream patch has been applied on libcurl to fix this
bug. As a result, the write after close no longer happens, and the SSL
library no longer leaks memory. (BZ#1092479)

  * Previously, the libcurl library did not implement a non-blocking SSL
handshake, which negatively affected performance of applications based on
libcurl's multi API. To fix this bug, the non-blocking SSL handshake has
been implemented by libcurl. With this update, libcurl's multi API
immediately returns the control back to the application whenever it cannot
read/write data from/to the underlying network socket. (BZ#1092480)

  * Previously, the curl package could not be rebuilt from sources due to an
expired cookie in the upstream test-suite, which runs during the build. An
upstream patch has been applied to postpone the expiration date of the
cookie, which makes it possible to rebuild the package from sources again.
(BZ#1092486)

  * Previously, the libcurl library attempted to authenticate using Kerberos
whenever such an authentication method was offered by the server. This
caused problems when the server offered multiple authentication methods and
Kerberos was not the selected one. An upstream patch has been applied on
libcurl to fix this bug. Now libcurl no longer uses Kerberos authentication
if another authentication method is selected. (BZ#1096797)

All curl users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running
applications that use libcurl have to be restarted for this update to
take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-May/020321.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
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

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.19.7~37.el6_5.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.19.7~37.el6_5.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.19.7~37.el6_5.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
