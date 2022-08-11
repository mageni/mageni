###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_log_insight_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# VMware vRealize Log Insight Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105751");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-10 11:52:17 +0200 (Fri, 10 Jun 2016)");
  script_name("VMware vRealize Log Insight Detection");

  script_tag(name:"summary", value:"This script perform ssh based detection of VMware vRealize Log Insight");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vrealize_log_insight_web_interface_detect.nasl");
  script_mandatory_keys("vmware/vrealize_log_insight/rls");
  exit(0);
}

include("host_details.inc");

if( ! rls = get_kb_item( "vmware/vrealize_log_insight/rls" ) ) exit( 0 );

cpe = 'cpe:/a:vmware:vrealize_log_insight';
vers = "unknown";

# VMware vRealize Log Insight 3.0.0 Build 3021606
version = eregmatch( pattern:'VMware vRealize Log Insight ([0-9]+[^ ]+) Build ([0-9]+[^ \r\n]+)', string:rls );

if( ! isnull( version[1] ) )
{
vers = version[1];
rep_vers = vers;
set_kb_item( name:"vmware/vrealize_log_insight/version", value:vers );
cpe += ':' + vers;
}

if( ! isnull( version[2] ) )
{
build = version[2];
set_kb_item( name:"vmware/vrealize_log_insight/build", value:build );
rep_vers = rep_vers + ' Build ' + build;
}

source = 'ssh';
if( "ds:www" >< rls ) source = 'www';

register_product( cpe:cpe, location:source );

log_message( port:0, data: build_detection_report( app:"VMware vRealize Log Insight", version:rep_vers, install:source, cpe:cpe, concluded:version[0] ) );
exit( 0 );

