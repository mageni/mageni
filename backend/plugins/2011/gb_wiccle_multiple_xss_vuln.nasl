###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wiccle_multiple_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Wiccle Web Builder CMS and iWiccle CMS Community Builder Multiple XSS Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802228");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_bugtraq_id(44295);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Wiccle Web Builder CMS and iWiccle CMS Community Builder Multiple XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=130");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62726");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_Wiccle_Web_Builder_and_iWiccle_CMS_Community_Builder.txt");
  script_xref(name:"URL", value:"http://www.wiccle.com/news/backstage_news/iwiccle/post/iwiccle_cms_community_builder_130_releas");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected application/site.");
  script_tag(name:"affected", value:"Wiccle Web Builder CMS version 1.0.1 and prior.
  iWiccle CMS Community Builder version 1.2.1.1 and prior.");
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input passed via
  the 'member_city', 'post_name', 'post_text', 'post_tag', 'post_member_name',
  'member_username' and  'member_tags' parameters to 'index.php', that allows
  attackers to execute arbitrary HTML and script code on the web server.");
  script_tag(name:"summary", value:"The host is running Wiccle Web Builder or iWiccle CMS Community
  Builder and is prone to multiple cross site scripting vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Wiccle Web Builder CMS version 1.1.0 or later, Upgrade to iWiccle CMS Community Builder version 1.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.wiccle.com/page/download_wiccle");
  script_xref(name:"URL", value:"http://www.wiccle.com/page/download_iwiccle");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list_unique("/wwb", "/iwiccle", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/index.php?module=site&show=home", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if(">Powered by Wiccle<" >< res)
  {
    url = string(dir, "/index.php?module=members&show=member_search&member_",
                            "username=<script>alert('XSS-Test')<%2Fscript>");

    if(http_vuln_check(port:port, url:url,
       pattern:"><script>alert\('XSS-Test'\)</script>", check_header:TRUE))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
