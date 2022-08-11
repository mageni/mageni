###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for httpd RHSA-2017:0906-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871799");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-04-13 06:32:47 +0200 (Thu, 13 Apr 2017)");
  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-8743");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for httpd RHSA-2017:0906-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The httpd packages provide the Apache HTTP
  Server, a powerful, efficient, and extensible web server.

Security Fix(es):

  * It was discovered that the mod_session_crypto module of httpd did not use
any mechanisms to verify integrity of the encrypted session data stored in
the user's browser. A remote attacker could use this flaw to decrypt and
modify session data using a padding oracle attack. (CVE-2016-0736)

  * It was discovered that the mod_auth_digest module of httpd did not
properly check for memory allocation failures. A remote attacker could use
this flaw to cause httpd child processes to repeatedly crash if the server
used HTTP digest authentication. (CVE-2016-2161)

  * It was discovered that the HTTP parser in httpd incorrectly allowed
certain characters not permitted by the HTTP protocol specification to
appear unencoded in HTTP request headers. If httpd was used in conjunction
with a proxy or backend server that interpreted those characters
differently, a remote attacker could possibly use this flaw to inject data
into HTTP responses, resulting in proxy cache poisoning. (CVE-2016-8743)

Note: The fix for the CVE-2016-8743 issue causes httpd to return '400 Bad
Request' error to HTTP clients which do not strictly follow HTTP protocol
specification. A newly introduced configuration directive
'HttpProtocolOptions Unsafe' can be used to re-enable the old less strict
parsing. However, such setting also re-introduces the CVE-2016-8743 issue.

Bug Fix(es):

  * When waking up child processes during a graceful restart, the httpd
parent process could attempt to open more connections than necessary if a
large number of child processes had been active prior to the restart.
Consequently, a graceful restart could take a long time to complete. With
this update, httpd has been fixed to limit the number of connections opened
during a graceful restart to the number of active children, and the
described problem no longer occurs. (BZ#1420002)

  * Previously, httpd running in a container returned the 500 HTTP status
code (Internal Server Error) when a connection to a WebSocket server was
closed. As a consequence, the httpd server failed to deliver the correct
HTTP status and data to a client. With this update, httpd correctly handles
all proxied requests to the WebSocket server, and the described problem no
longer occurs. (BZ#1429947)

  * In a configuration using LDAP authentication with the mod_authnz_ldap
module, the name set using the AuthLDAPBindDN directive was not correctly
used to bind to the LDAP server for all queries. Consequently,
authorization attempts failed. The LDAP modules have been fixed to ensure
the configured name is correctly bound for LDAP queries, and authorization
using LDAP no longer fails. (BZ#1420047)");
  script_tag(name:"affected", value:"httpd on
  Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-April/msg00021.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.4.6~45.el7_3.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.6~45.el7_3.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.4.6~45.el7_3.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.4.6~45.el7_3.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.6~45.el7_3.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.6~45.el7_3.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
