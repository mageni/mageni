###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_threat_discovery_eol.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Trend Micro Threat Discovery Appliance EOL
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.140248");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11408 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-04-12 09:30:26 +0200 (Wed, 12 Apr 2017)");
  script_name("Trend Micro Threat Discovery Appliance EOL");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1105727-list-of-end-of-life-eol-end-of-support-eos-trend-micro-products");

  script_tag(name:"summary", value:"The remote Trend Micro Threat Discovery Appliance has reached EOL at 30-Jun-16. There are known security issues with this
  appliances which are not longer patched.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
buf = http_get_cache( port:port, item:"/" );

if( "title>Trend Micro Threat Discovery Appliance Logon</title>" >< buf && "Trend Micro Incorporated" >< buf )
{
  cpe = 'cpe:/a:trendmicro:threat_discovery';
  register_product( cpe:cpe, location:"/", port:port, service:"www" );
  security_message( port:port );
  exit( 0 );
}

exit( 0 );
