###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2011-9.nasl 11703 2018-10-01 08:05:31Z cfischer $
#
# Amazon Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@iki.fi>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120513");
  script_version("$Revision: 11703 $");
  script_tag(name:"creation_date", value:"2015-09-08 11:27:36 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 10:05:31 +0200 (Mon, 01 Oct 2018) $");
  script_name("Amazon Linux Local Check: ALAS-2011-9");
  script_tag(name:"insight", value:"It was discovered that the Apache HTTP Server did not properly validate the request URI for proxied requests. In certain configurations, if a reverse proxy used the ProxyPassMatch directive, or if it used the RewriteRule directive with the proxy flag, a remote attacker could make the proxy connect to an arbitrary server, possibly disclosing sensitive information from internal web servers not directly accessible to the attacker. (CVE-2011-3368 )It was discovered that mod_proxy_ajp incorrectly returned an Internal Server Error response when processing certain malformed HTTP requests, which caused the back-end server to be marked as failed in configurations where mod_proxy was used in load balancer mode. A remote attacker could cause mod_proxy to not send requests to back-end AJP (Apache JServ Protocol) servers for the retry timeout period or until all back-end servers were marked as failed. (CVE-2011-3348 )");
  script_tag(name:"solution", value:"Run yum update httpd to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2011-9.html");
  script_cve_id("CVE-2011-3368", "CVE-2011-3348");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
  script_copyright("Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.21~1.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.21~1.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.21~1.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.21~1.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.21~1.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
