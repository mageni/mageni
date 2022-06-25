###############################################################################
# OpenVAS Vulnerability Test
# $Id: AnswerBook2_12746.nasl 14330 2019-03-19 13:59:11Z asteins $
#
# Sun Solaris AnswerBook2 Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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



if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100388");
  script_version("$Revision: 14330 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:59:11 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-10 18:09:58 +0100 (Thu, 10 Dec 2009)");
  script_bugtraq_id(12746);
  script_cve_id("CVE-2005-0548", "CVE-2005-0549");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Sun Solaris AnswerBook2 Multiple Cross-Site Scripting Vulnerabilities");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8888);
  script_mandatory_keys("dwhttpd/banner");
  script_tag(name:"solution", value:"Sun has released a advisory to address these issues. The vendor
recommends disabling the application and referring to Sun
documentation at the Sun Product Documentation Web site.

Please see the referenced advisory for more information.");
  script_tag(name:"summary", value:"Sun Solaris AnswerBook2 is reported prone to multiple cross-site
scripting vulnerabilities. These issues arise due to insufficient
sanitization of user-supplied data facilitating execution of arbitrary
HTML and script code in a user's browser.");

  script_tag(name:"insight", value:"The following specific issues were identified:

It is reported that the Search function of the application is affected
by a cross-site scripting vulnerability.

The AnswerBook2 admin interface is prone to cross-site scripting
attacks as well.");

  script_tag(name:"impact", value:"These issues can lead to theft of cookie based credentials and
other attacks.");

  script_tag(name:"affected", value:"AnswerBook2 1.4.4 and prior versions are affected by these issues.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12746");
  script_xref(name:"URL", value:"http://wwws.sun.com/software//ab2/");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-57737-1&searchclause=%22category:security%22%20%22availability,%20security%22");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/394429");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-200305-1");
  script_xref(name:"URL", value:"http://docs.sun.com");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8888);

banner = get_http_banner(port: port);
if("dwhttpd" >!< banner)exit(0);

url = string("/ab2/Help_C/@Ab2HelpSearch?scope=HELP&DwebQuery=%3Cscript%3Ealert(%27OpenVAS-XSS-Test%27)%3C/script%3E&Search=+Search+");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);
if( buf == NULL )continue;

if(buf =~ "HTTP/1\.. 200" && egrep(pattern: "<script>alert\('OpenVAS-XSS-Test'\)</script>", string: buf, icase: TRUE)) {

  security_message(port:port, data:"The target host was found to be vulnerable.");
  exit(0);
}

exit(99);
