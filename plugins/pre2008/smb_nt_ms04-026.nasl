###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_nt_ms04-026.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (842436)
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Tenable adds
# - check for OWA on port 80
# Updated: 2009/04/23 Chandan S <schandan@secpod.com>
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

# Ref: Amit Klein (August 2004)

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14254");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10902);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-0203");
  script_name("Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (842436)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"This vulnerability could allow an attacker to convince a user
  to run a malicious script. If this malicious script is run, it would execute
  in the security context of the user.
  Attempts to exploit this vulnerability require user interaction.

  This vulnerability could allow an attacker access to any data on the
  Outlook Web Access server that was accessible to the individual user.

  It may also be possible to exploit the vulnerability to manipulate Web browser caches
  and intermediate proxy server caches, and put spoofed content in those caches.");

  script_tag(name:"solution", value:"Apply the Windows Updates described in the references.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms04-026.mspx");

  script_tag(name:"summary", value:"The remote host is running a version of the Outlook Web Access which contains
  cross site scripting flaws.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("secpod_reg.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

cgi = "/exchange/root.asp";
if( ! is_cgi_installed_ka( item:cgi, port:port ) ) exit( 0 );

# now check for the patch
if( hotfix_check_nt_server() <= 0 ) exit( 0 );

vers = hotfix_check_exchange_installed();
if( isnull( vers ) ) exit( 0 );

if( hotfix_missing( name:"KB842436" ) > 0 )
  security_message( port:0 );
