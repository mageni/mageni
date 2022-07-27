###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edirectory_40541.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Novell eDirectory Multiple Remote Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.100667");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-04 13:05:19 +0200 (Fri, 04 Jun 2010)");
  script_bugtraq_id(40541);
  script_cve_id("CVE-2009-4653");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("Novell eDirectory Multiple Remote Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("novell_edirectory_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("eDirectory/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40541");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_xref(name:"URL", value:"http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5076150.html");
  script_xref(name:"URL", value:"http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5076151.html");
  script_xref(name:"URL", value:"http://www.novell.com/products/edirectory/");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for details.");
  script_tag(name:"summary", value:"Novell eDirectory is prone to multiple remote vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploits may allow attackers to execute arbitrary code
  within the context of the affected application or cause denial-of-service conditions.");
  script_tag(name:"affected", value:"These issues affect eDirectory versions prior to 8.8 SP5 Patch 4.");

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

if(  major == "8.8" )
{
  if( sp && sp > 0 )
  {
    if( sp == 5 )
    {
      if( revision && int( revision ) < 2050413 )
      { # < eDirectory 8.8 SP5 Patch 4 (20504.13)
        vuln = TRUE;
      }
    } else
    {
      if( sp < 5 )
      {
        vuln = TRUE;
      }
    }
  } else
  {
    vuln = TRUE;
  }
}

if( vuln )
{
  report = report_fixed_ver( installed_version:reportver, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit(0);
}

exit( 99 );