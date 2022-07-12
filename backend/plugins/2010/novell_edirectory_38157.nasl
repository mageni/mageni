###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_edirectory_38157.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Novell eDirectory eMBox SOAP Request Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Updated the CVE.
#  - Rachana Shetty <srachana@secpod.com> on 2010-02-22 #7360
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100492");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-10 12:17:39 +0100 (Wed, 10 Feb 2010)");
  script_cve_id("CVE-2010-0666");
  script_bugtraq_id(38157);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Novell eDirectory eMBox SOAP Request Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("novell_edirectory_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("eDirectory/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38157");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_xref(name:"URL", value:"http://www.novell.com");

  script_tag(name:"summary", value:"Novell eDirectory is prone to a denial-of-service vulnerability.");
  script_tag(name:"impact", value:"Remote attackers can exploit this issue to crash the application,
  denying service to legitimate users.");
  script_tag(name:"affected", value:"Versions prior to Novell eDirectory 8.8 SP5 Patch 3 are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = make_list( "cpe:/a:novell:edirectory","cpe:/a:netiq:edirectory" );

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! major = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

reportver = major;

if( sp > 0 )
  reportver += ' SP' + sp;

revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );
revision = str_replace( string:revision, find:".", replace:"" );

if( major == "8.8" )
{
  if( sp && sp > 0 )
  {
    if( sp == 5 )
    {
      if( revision && revision < 2050315 )
      { # < eDirectory 8.8 SP5 Patch 3 (20503.15)
        vuln = TRUE;
      }
    } else
    {
      if( sp < 5 )
      {
        vuln = TRUE;
      }
    }
  } else {
    vuln = TRUE;
  }
}

if(vuln) {
  report = report_fixed_ver( installed_version:reportver, fixed_version:"See advisory" );
  security_message(port:port, data:report );
  exit(0);
}

exit(99);