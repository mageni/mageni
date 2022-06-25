###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_data_loss_prevention_detect.nasl 12017 2018-10-22 13:26:58Z cfischer $
#
# Trend Micro Data Loss Prevention Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103181");
  script_version("$Revision: 12017 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:26:58 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-14 13:57:36 +0200 (Tue, 14 Jun 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Trend Micro Data Loss Prevention Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://us.trendmicro.com/us/products/enterprise/data-loss-prevention/index.html");

  script_tag(name:"summary", value:"This host is running Trend Micro Data Loss Prevention, a network and
  endpoint-based data loss prevention (DLP) solution.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8443 );

url = "/dsc";
buf = http_get_cache( item:url + "/", port:port );
if( ! buf ) exit(0);

if( match = egrep( pattern:"<title>Trend Micro Data Loss Prevention Logon", string:buf, icase:TRUE ) )  {
  version = "unknown";
  set_kb_item( name:"trendmicro/datalossprevention/detected", value:TRUE );
  register_and_report_cpe( app:"Trend Micro Data Loss Prevention", ver:version, concluded:match, conclUrl:url, base:"cpe:/a:trend_micro:data_loss_prevention:", expr:"^([0-9.]+)", insloc:url, regPort:port, regService:"www" );
}

exit( 0 );