###############################################################################
# OpenVAS Vulnerability Test
# $Id: fspd_directory_traversal.nasl 4922 2017-01-02 16:28:42Z cfi $
#
# FSP Suite Directory Traversal Vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11988");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1022");
  script_bugtraq_id(9377);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FSP Suite Directory Traversal Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Remote file access");
  script_dependencies("fsp_detection.nasl");
  script_mandatory_keys("fsp_compatible_host/identified");

  script_tag(name:"summary", value:"The FSP Suite (daemon) has been found to improperly filter out
  paths with trailing / or starting with /. This would allow an attacker
  access to files that reside outside the bounding FSP root directory.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

banners = get_kb_list( "fsp/banner/*" );
if( isnull( banners ) ) exit( 0 );

foreach k( keys( banners ) ) {
  port   = int( k - "fsp/banner/" );
  banner = banners[k];

  if( egrep( string:banner, pattern:"fspd (2\.8\.1b1[0-7]|2\.8\.0|2\.[0-7]\.|[0-1]\.)" ) ) {
    security_message( port:port, protocol:"udp" );
    exit( 0 );
  }
}

exit( 99 );