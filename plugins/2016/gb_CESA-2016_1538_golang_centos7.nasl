###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for golang CESA-2016:1538 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882533");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-08 15:11:58 +0530 (Mon, 08 Aug 2016)");
  script_cve_id("CVE-2016-5386");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for golang CESA-2016:1538 centos7");
  script_tag(name:"summary", value:"Check the version of golang");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The golang packages provide the
Go programming language compiler.

The following packages have been upgraded to a newer upstream version:
golang (1.6.3). (BZ#1346331)

Security Fix(es):

  * An input-validation flaw was discovered in the Go programming language
built in CGI implementation, which set the environment variable
'HTTP_PROXY' using the incoming 'Proxy' HTTP-request header. The
environment variable 'HTTP_PROXY' is used by numerous web clients,
including Go's net/http package, to specify a proxy server to use for HTTP
and, in some cases, HTTPS requests. This meant that when a CGI-based web
application ran, an attacker could specify a proxy server which the
application then used for subsequent outgoing requests, allowing a
man-in-the-middle attack. (CVE-2016-5386)

Red Hat would like to thank Scott Geary (VendHQ) for reporting this issue.");
  script_tag(name:"affected", value:"golang on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-August/022005.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"golang", rpm:"golang~1.6.3~1.el7_2.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.6.3~1.el7_2.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.6.3~1.el7_2.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.6.3~1.el7_2.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.6.3~1.el7_2.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.6.3~1.el7_2.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
