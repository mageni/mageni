###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sgx-sp_final_mult_xss_vuln.nasl 12010 2018-10-22 08:23:57Z mmartin $
#
# SGX-SP Final 'shop.cgi' Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902532");
  script_version("$Revision: 12010 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:23:57 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2010-3926");
  script_bugtraq_id(45752);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("SGX-SP Final 'shop.cgi' Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://wb-i.net/soft1.HTML#spf");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42857");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64593");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"SGX-SP Final version 10.0 and prior.");
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input passed to
  shop.cgi, which allows attackers to execute arbitrary HTML and script code
  in a user's browser session in context of an affected site.");
  script_tag(name:"solution", value:"Upgrade to SGX-SP Final version 11.0 or later.");
  script_tag(name:"summary", value:"This host is running SGX-SP Final and is prone to multiple cross
  site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/SPF", "/shop", "/mall", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/shop.cgi",  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ver = eregmatch(pattern:'SGX-SPF Ver([0-9.]+)', string:res);
  if(ver[1])
  {
    if(version_is_less(version:ver[1], test_version:"11.00"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);