###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_http_server_mult_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# IBM HTTP Server Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801996");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-1360");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-08 19:48:57 +0530 (Tue, 08 Nov 2011)");
  script_name("IBM HTTP Server Multiple Cross Site Scripting Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 8880, 8008);
  script_mandatory_keys("IBM_HTTP_Server/banner");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"IBM HTTP Server version 2.0.47 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input
  by a documentation page located in the 'manual/ibm' sub directories. That
  allows attackers to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site.");
  script_tag(name:"summary", value:"This host is running IBM HTTP Server and is prone to multiple cross
  site scripting vulnerabilities.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.
  *****
  NOTE: Please ignore this warning if the mentioned patch is already applied.
  *****");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69656");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21502580");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&context=SSEQTP&dc=D600&uid=swg21502580");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

ibmWebSer = get_http_banner(port:port);

  if("Server: IBM_HTTP_Server" >< ibmWebSer)
  {
    ver = eregmatch(pattern:"IBM_HTTP_Server/([0-9.]+)", string:ibmWebSer);
    if(ver[1])
    {
      if(version_is_less_equal(version:ver[1], test_version:"2.0.47"))
      {
        security_message(port);
        exit(0);
      }
    }
  }
