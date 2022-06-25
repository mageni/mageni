###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for httpd CESA-2009:1579 centos3 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.880739");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");
  script_name("CentOS Update for httpd CESA-2009:1579 centos3 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-November/016316.html");
  script_xref(name:"URL", value:"http://kbase.redhat.com/faq/docs/DOC-20491");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"httpd on CentOS 3");
  script_tag(name:"insight", value:"The Apache HTTP Server is a popular Web server.

  A flaw was found in the way the TLS/SSL (Transport Layer Security/Secure
  Sockets Layer) protocols handle session renegotiation. A man-in-the-middle
  attacker could use this flaw to prefix arbitrary plain text to a client's
  session (for example, an HTTPS connection to a website). This could force
  the server to process an attacker's request as if authenticated using the
  victim's credentials. This update partially mitigates this flaw for SSL
  sessions to HTTP servers using mod_ssl by rejecting client-requested
  renegotiation. (CVE-2009-3555)

  Note: This update does not fully resolve the issue for HTTPS servers. An
  attack is still possible in configurations that require a server-initiated
  renegotiation. Refer to the linked Knowledgebase article for further
  information.

  A NULL pointer dereference flaw was found in the Apache mod_proxy_ftp
  module. A malicious FTP server to which requests are being proxied could
  use this flaw to crash an httpd child process via a malformed reply to the
  EPSV or PASV commands, resulting in a limited denial of service.
  (CVE-2009-3094)

  A second flaw was found in the Apache mod_proxy_ftp module. In a reverse
  proxy configuration, a remote attacker could use this flaw to bypass
  intended access restrictions by creating a carefully-crafted HTTP
  Authorization header, allowing the attacker to send arbitrary commands to
  the FTP server. (CVE-2009-3095)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.0.46~77.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.0.46~77.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.0.46~77.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
