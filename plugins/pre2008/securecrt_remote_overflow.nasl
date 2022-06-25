###############################################################################
# OpenVAS Vulnerability Test
# $Id: securecrt_remote_overflow.nasl 10200 2018-06-14 14:39:20Z cfischer $
#
# SecureCRT SSH1 protocol version string overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

#  Ref: Kyuzo <ogl@SirDrinkalot.rm-f.net>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15822");
  script_version("$Revision: 10200 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-14 16:39:20 +0200 (Thu, 14 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1059");
  script_bugtraq_id(5287);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SecureCRT SSH1 protocol version string overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"The remote host is using a vulnerable version of SecureCRT, a
  SSH/Telnet client built for Microsoft Windows operation systems.");

  script_tag(name:"impact", value:"It has been reported that SecureCRT contain a remote buffer overflow
  allowing an SSH server to execute arbitrary command via a specially
  long SSH1 protocol version string.");

  script_tag(name:"solution", value:"Upgrade to SecureCRT 3.2.2, 3.3.4, 3.4.6, 4.1 or newer");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");

key_list = make_list( "SOFTWARE\VanDyke\SecureCRT\License\",
                      "SOFTWARE\VanDyke\SecureCRT\Evaluation License\" );

foreach key( key_list ) {

  if( ! registry_key_exists( key:key ) ) continue;

  version = registry_get_sz( key:key, item:"Version" );
  if( version && egrep( pattern:"^(2\.|3\.([01]|2[^.]|2\.1[^0-9]|3[^.]|3\.[1-3][^0-9]|4[^.]|4\.[1-5][^0-9])|4\.0 beta [12])", string:version ) ) {
    security_message( port:0 );
    exit( 0 );
  }
}

exit( 99 );