###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snowfox_cms_rd_open_redirect_vuln.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Snowfox CMS 'rd' Parameter Open Redirect Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805208");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-9343");
  script_bugtraq_id(71174);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-11 18:21:19 +0530 (Thu, 11 Dec 2014)");
  script_name("Snowfox CMS 'rd' Parameter Open Redirect Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Snowfox CMS
  and is prone to open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it redirects to the malicious websites.");

  script_tag(name:"insight", value:"The error exists as the application does
  not validate the 'rd' parameter upon submission to the selectlanguage.class.php
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing.");

  script_tag(name:"affected", value:"Snowfox CMS version 1.0");

  script_tag(name:"solution", value:"Upgrade to Snowfox CMS version 1.0.10 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.zeroscience.mk/codes/snowfox_url.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129162");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.snowfoxcms.org/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

cmsPort = get_http_port(default:80);

if(!can_host_php(port:cmsPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/snowfox", "/snowfoxcms", "/cms", cgi_dirs(port:cmsPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:cmsPort);

  if(rcvRes && rcvRes =~ "powered by.*>Snowfox CMS<")
  {
    url = dir + "/?uri=user/select-language&formAction=submit&rd=ht"
              + "tp://www.example.com";

    sndReq = http_get(item:url,  port:cmsPort);
    rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

    if(rcvRes && rcvRes =~ "HTTP/1.. 302" &&
       rcvRes =~ "(L|l)ocation: http://www.example.com")
    {
      security_message(port:cmsPort);
      exit(0);
    }
  }
}

exit(99);