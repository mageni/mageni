###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_edirectory_37009.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Novell eDirectory '/dhost/modules?I:' Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100343");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-11-13 12:21:24 +0100 (Fri, 13 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4653");
  script_bugtraq_id(37009);
  script_name("Novell eDirectory '/dhost/modules?I:' Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("novell_edirectory_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("eDirectory/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37009");
  script_xref(name:"URL", value:"http://www.novell.com/products/edirectory/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507812");

  script_tag(name:"summary", value:"Novell eDirectory is prone to a buffer-overflow vulnerability
  because it fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will likely cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Novell eDirectory 8.8 SP5 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = make_list( "cpe:/a:novell:edirectory","cpe:/a:netiq:edirectory" );

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! major = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );

instver = major;

if( sp > 0 )
  instver += ' SP' + sp;

if( major == "8.8" )
{
  if( sp && sp > 0 )
  {
    if( sp == 5 )
    {
      if( ! revision )
      {
        VULN = TRUE;
      }
    }
    if( sp < 5 )
    {
      VULN = TRUE;
    }
  } else {
     VULN = TRUE;
   }
}
else if( major == "8.8.1" )
{
  VULN = TRUE;
}
else if( major == "8.8.2" )
{
  if( ! revision && ! sp )
  {
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver( installed_version:instver, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit(0);
}

exit(99);