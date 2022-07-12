###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_default_welcome_page_info_disc_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Microsoft IIS Default Welcome Page Information Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:microsoft:iis';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802806");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-02-23 16:21:11 +0530 (Thu, 23 Feb 2012)");
  script_name("Microsoft IIS Default Welcome Page Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_mandatory_keys("IIS/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information that could aid in further attacks.");
  script_tag(name:"affected", value:"Microsoft Internet Information Services");
  script_tag(name:"insight", value:"The flaw is due to misconfiguration of IIS Server, which allows to
  access default pages when the server is not used.");
  script_tag(name:"summary", value:"The host is running Microsoft IIS Webserver and is prone to
  information disclosure vulnerability.");
  script_tag(name:"solution", value:"Disable the default pages within the server configuration.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  script_xref(name:"URL", value:"http://www.iis.net/");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! iisPort = get_app_port( cpe:CPE ) ) exit( 0 );

##Send Request for default page
response = http_get_cache(item:"/", port:iisPort);

if(response && (
   (("<title id=titletext>Under Construction</title>" ><response) && ("The site you were trying to reach does not currently have a default page" >< response)) ||
   (("welcome to iis 4.0" >< response) && ("microsoft windows nt 4.0 option pack" >< response)) ||
   (("<title>iis7</title>" >< response) && ('<img src="welcome.png" alt="iis7"' >< response)) ||
   (("<title>IIS7</title>" >< response) && ('<img src="welcome.png" alt="IIS7"' >< response))
  )){
  security_message(port:iisPort);
  exit(0);
}

exit(99);
