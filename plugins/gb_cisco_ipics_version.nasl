###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ipics_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco IP Interoperability and Collaboration System Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105601");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-11 13:25:26 +0200 (Mon, 11 Apr 2016)");
  script_name("Cisco IP Interoperability and Collaboration System Version Detection");

  script_tag(name:"summary", value:"This Script performs SSH based detection of Cisco IP Interoperability and Collaboration System");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco/ipics/detected");
  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if( ! get_kb_item( "cisco/ipics/detected" ) ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

ipics_version = ssh_cmd( socket:sock, cmd:'/opt/cisco/ipics/bin/versions');
# Example response:
#
# ------------------------------------------------------------------------------
# OS
# ------------------------------------------------------------------------------
# Version        : Cisco IPICS Enterprise Linux Server release 4.5(1) Build 10p12
# Built          : Mon Oct 06 2014 16:27:39 GMT
# Installed      : Wed Dec 16 2015 19:40:24 GMT
#
# ------------------------------------------------------------------------------
# 3rd Party
# ------------------------------------------------------------------------------
# Java           : 1.6.0_81
# Tomcat (UMS)   : 7.0.29
# OpenSSH        : 4.3p2-82.el5
# OpenSSL        : 0.9.8e-36.el5_11
#
# ------------------------------------------------------------------------------
# UMS
# ------------------------------------------------------------------------------
# Version   (RPM): 4.10(1)
# Built     (RPM): Thu Jan 14 2016 04:00:07 GMT
# Installed (RPM): Mon Apr 11 2016 05:16:10 GMT
#
# ------------------------------------------------------------------------------
# Installed RPM's:
# ------------------------------------------------------------------------------
# ipics-bin-4.10-1
# ipics-logos-4.5-1
# ipics-nodemanager-4.10-1
# ipics-rcs-4.10-1
# ipics-security-4.10-1
# ipics-splash-4.10-1
# ipics-stig-4.10-1
# ipics-tools-5.5-3.1
# ums-4.10-1

close( sock );

if("UMS" >!< ipics_version ) exit( 0 );

set_kb_item( name:'cisco/ipics/ipics_bin_versions', value:ipics_version );

vers = 'unknown';
cpe = 'cpe:/a:cisco:ip_interoperability_and_collaboration_system';

version = eregmatch( pattern:'UMS\\s*[\r\n]+[-]+[\r\n]+Version\\s*\\(RPM\\):\\s*([0-9]+[^\r\n]+)', string: ipics_version );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:'cisco/ipics/version', value:vers ); # 4.10(1)
}

register_product( cpe:cpe, location:"ssh" );

report = build_detection_report( app:'Cisco IP Interoperability and Collaboration System', version:vers, install:"ssh", cpe:cpe, concluded:version[0] );
log_message( port:0, data:report );
exit( 0 );

