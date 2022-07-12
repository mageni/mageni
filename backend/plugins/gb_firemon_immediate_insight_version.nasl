###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firemon_immediate_insight_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# FireMon Immediate Insight Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140107");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-29 10:07:33 +0100 (Thu, 29 Dec 2016)");
  script_name("FireMon Immediate Insight Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of FireMon Immediate Insight");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "firemon/immediate_insight/detected");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if( ! port = kb_ssh_transport() ) exit( 0 );
if( ! sock = ssh_login_or_reuse_connection() ) exit( 0 );

buf = ssh_cmd( socket:sock, cmd:"PATH=/home/insight/app/utils/:$PATH /home/insight/app/utils/status" );
# System Status - Quick Check
# =============================
# --------------------------------------------------------------------
# Server IP: 192.168.2.51
# Personality: server
#
# Immediate Insight 2016 -- version: app-2016-10-18
# Search engine version: search-2.1.2
#
# Data Marshal: Running
# UI Marshal: Running
# Marshal Server: Running
# Agent: Running
# Search Engine: Running
# Search Engine Health: green
# Search Engine Memory: 4GB
#
# Data Storage (pct used):   1%
# System Storage (pct used):  27%
# System Log Storage (pct used):   1%
#
# Total System RAM: 7GB
# Free System RAM: 2GB
# %Cpu(s):  0.4 us,  0.3 sy,  0.0 ni, 99.2 id,  0.0 wa,  0.0 hi,  0.1 si,  0.0 st
#
# DNS Servers: 192.168.2.1
# Internet Access: yes
# Server Time: Thu Dec 29 10:16:40 CET 2016
# Server Timezone: Europe/Berlin
# NTP Servers: time.nist.gov time-nw.nist.gov

close( sock );

if( "Immediate Insight" >!< buf ) exit( 0 );

set_kb_item( name:"firemon/immediate_insight/status", value:buf );

cpe = 'cpe:/a:firemon:immediate_insight';
version = 'unknown';

lines = split( buf );

foreach line ( lines )
{
  if( line =~ 'Immediate Insight.* version: ' )
  {
    v = eregmatch( pattern:'Immediate Insight.* version: ([^\r\n]+)', string:line );
    break;
  }
}

if( ! isnull( v[1] ) )
{
  version = v[1]; # app-2016-10-18
  cpe += ':' + version;
  set_kb_item( name:"firemon/immediate_insight/version", value:version );
}

register_product( cpe:cpe, location:"ssh", port:port, service:"ssh" );

report = build_detection_report( app:"FireMon Immediate Insight", version:version, install:"ssh", cpe:cpe, concluded:v[0] );

log_message( port:port, data:report );

exit( 0 );

