###############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_mod_include_priv_escalation.nasl 9229 2018-03-28 06:24:54Z cfischer $
#
# Apache mod_include privilege escalation
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

#  Ref: Crazy Einstein

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15554");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11471);
  script_cve_id("CVE-2004-0940");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apache mod_include privilege escalation");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_tag(name:"summary", value:"The remote web server appears to be running a version of Apache that is older
  than version 1.3.33.");

  script_tag(name:"insight", value:"This version is vulnerable to a local buffer overflow in the get_tag()
  function of the module 'mod_include' when a specially crafted document
  with malformed server-side includes is requested though an HTTP session.");

  script_tag(name:"impact", value:"Successful exploitation can lead to execution of arbitrary code with
  escalated privileges, but requires that server-side includes (SSI) is enabled.");

  script_tag(name:"solution", value:"Disable SSI or upgrade to a newer version when available.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );

serv = strstr( banner, "Server" );
if( ereg( pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.|3\.([0-9][^0-9]|[0-2][0-9]|3[0-2])))", string:serv ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );