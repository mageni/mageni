###############################################################################
# OpenVAS Vulnerability Test
# $Id: iis_nat.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# Private IP address leaked in HTTP headers
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by Paul Johnston for Westpoint Ltd <paul@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com, 2003 Westpoint Ltd
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10759");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1499);
  script_cve_id("CVE-2000-0649");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_name("Private IP address leaked in HTTP headers");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Alert4Web.com, 2003 Westpoint Ltd");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("keys/is_private_addr", "Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/218180");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1499/");
  script_xref(name:"URL", value:"http://foofus.net/?p=758");

  script_tag(name:"summary", value:"This web server leaks a private IP address through its HTTP headers.");

  script_tag(name:"impact", value:"This may expose internal IP addresses that are usually hidden or masked
  behind a Network Address Translation (NAT) Firewall or proxy server.");

  script_tag(name:"insight", value:"There is a known issue with IIS 4.0 doing this in its default configuration.
  Furthermore Microsoft Exchange CAS and OWA as well as other webservers or load balancers might be also affected.");

  script_tag(name:"solution", value:"See the references for possible workarounds and updates.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); #TBD: remote_banner?

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("network_func.inc");

if( is_private_addr() ) exit( 0 );

port = get_http_port( default:80 );
useragent = http_get_user_agent();

foreach dir( make_list( "/", "/images", "/Autodiscover", "/Autodiscover/Autodiscover.xml", "/Microsoft-Server-ActiveSync",
                        "/Microsoft-Server-ActiveSync/default.css", "/ECP", "/EWS", "/EWS/Exchange.asmx", "/Exchange", "/OWA",
                        "/Microsoft-Server-ActiveSync/default.eas", "/Rpc", "/EWS/Services.wsdl", "/ecp", "/OAB", "/aspnet_client", "/PowerShell" ) ) {

  # Craft our own HTTP/1.0 request for the server banner.
  # Note: HTTP/1.1 is rarely useful for detecting this flaw.
  req = 'GET ' + dir + ' HTTP/1.0\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        '\r\n';
  buf = http_keepalive_send_recv( port:port, data:req );

  # nb: Check for private IP addresses in the banner
  # Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
  # TBD: regex for all IPv6 addresses and then pass to is_private_addr(addr, use_globals:FALSE) ?
  private_ip = eregmatch( pattern:"([^12]10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:buf );
  if( ! isnull( private_ip ) && ! egrep( pattern:"Oracle.*/10\.", string:buf ) ) {
    report = "This web server leaks the following private IP address : " + private_ip[0] + '\n\n';
    report += report_vuln_url( port:port, url:dir );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );