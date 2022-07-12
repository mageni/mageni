###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for httpd CESA-2010:0168 centos5 i386
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
  script_oid("1.3.6.1.4.1.25623.1.0.880565");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0408", "CVE-2010-0434");
  script_name("CentOS Update for httpd CESA-2010:0168 centos5 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-March/016603.html");
  script_xref(name:"URL", value:"http://kbase.redhat.com/faq/docs/DOC-20491");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"httpd on CentOS 5");
  script_tag(name:"insight", value:"The Apache HTTP Server is a popular web server.

  It was discovered that mod_proxy_ajp incorrectly returned an 'Internal
  Server Error' response when processing certain malformed requests, which
  caused the back-end server to be marked as failed in configurations where
  mod_proxy is used in load balancer mode. A remote attacker could cause
  mod_proxy to not send requests to back-end AJP (Apache JServ Protocol)
  servers for the retry timeout period (60 seconds by default) by sending
  specially-crafted requests. (CVE-2010-0408)

  A use-after-free flaw was discovered in the way the Apache HTTP Server
  handled request headers in subrequests. In configurations where subrequests
  are used, a multithreaded MPM (Multi-Processing Module) could possibly leak
  information from other requests in request replies. (CVE-2010-0434)

  This update also adds the following enhancement:

  * with the updated openssl packages from RHSA-2010:0162 installed, mod_ssl
  will refuse to renegotiate a TLS/SSL connection with an unpatched client
  that does not support RFC 5746. This update adds the
  'SSLInsecureRenegotiation' configuration directive. If this directive is
  enabled, mod_ssl will renegotiate insecurely with unpatched clients.
  (BZ#567980)

  Refer to the linked Red Hat Knowledgebase article for more details about
  the changed mod_ssl behavior.

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues and add this enhancement. After
  installing the updated packages, the httpd daemon must be restarted for the
  update to take effect.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~31.el5.centos.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~31.el5.centos.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~31.el5.centos.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~31.el5.centos.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
