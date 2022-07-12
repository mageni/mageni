###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for httpd CESA-2016:1422 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882521");
  script_version("$Revision: 14095 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 14:54:56 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-07-19 05:26:52 +0200 (Tue, 19 Jul 2016)");
  script_cve_id("CVE-2016-5387");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for httpd CESA-2016:1422 centos7");
  script_tag(name:"summary", value:"Check the version of httpd");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The httpd packages provide the Apache HTTP
Server, a powerful, efficient, and extensible web server.

Security Fix(es):

  * It was discovered that httpd used the value of the Proxy header from HTTP
requests to initialize the HTTP_PROXY environment variable for CGI scripts,
which in turn was incorrectly used by certain HTTP client implementations
to configure the proxy for outgoing HTTP requests. A remote attacker could
possibly use this flaw to redirect HTTP requests performed by a CGI script
to an attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-5387)

Note: After this update, httpd will no longer pass the value of the Proxy
request header to scripts via the HTTP_PROXY environment variable.

Red Hat would like to thank Scott Geary (VendHQ) for reporting this issue.

Bug Fix(es):

  * In a caching proxy configuration, the mod_cache module would treat
content as stale if the Expires header changed when refreshing a cached
response. As a consequence, an origin server returning content without a
fixed Expires header would not be treated as cacheable. The mod_cache
module has been fixed to ignore changes in the Expires header when
refreshing content. As a result, such content is now cacheable, improving
performance and reducing load at the origin server. (BZ#1347648)

  * The HTTP status code 451 'Unavailable For Legal Reasons' was not usable
in the httpd configuration. As a consequence, modules such as mod_rewrite
could not be configured to return a 451 error if required for legal
purposes. The 451 status code has been added to the list of available error
codes, and modules can now be configured to return a 451 error if required.
(BZ#1353269)

4. Solution:

For details on how to apply this update, which includes the changes
described in this advisory, refer to the linked article.

After installing the updated packages, the httpd daemon will be restarted
automatically.

5. Bugs fixed:

1347648 - Apache can not cache content if Expires header is modified
1353269 - Support sending http 451 status code from RewriteRule
1353755 - CVE-2016-5387 Apache HTTPD: sets environmental variable based on user supplied Proxy request header

6. Package List:

Red Hat Enterprise Linux Client Optional (v. 7):

Source:
httpd-2.4.6-40.el7_2.4.src.rpm

noarch:
httpd-manual-2.4.6-40.el7_2.4.noarch.rpm

x86_64:
httpd-2.4.6-40.el7_2.4.x86_64.rpm
httpd-debuginfo-2.4.6-40.el7_2.4.x86_64.rpm
httpd-devel-2.4.6-40.el7_2.4.x86_64.rpm
httpd- ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"httpd on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-July/021979.html");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/11258");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ldap", rpm:"mod_ldap~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_proxy_html", rpm:"mod_proxy_html~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_session", rpm:"mod_session~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
