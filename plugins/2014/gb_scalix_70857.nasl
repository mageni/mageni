###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_scalix_70857.nasl 14185 2019-03-14 13:43:25Z cfischer $
#
# Scalix Web Access XML External Entity Injection and Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:scalix:scalix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105103");
  script_cve_id("CVE-2014-9352", "CVE-2014-9360");
  script_bugtraq_id(70857, 70859);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 14185 $");

  script_name("Scalix Web Access XML External Entity Injection and Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70859");

  script_tag(name:"impact", value:"Attackers can exploit the XML External Entity Injection to
  obtain potentially sensitive information. This may lead to further attacks. An attacker may leverage
  the Cross Site Scripting issue to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site. This may allow the attacker to steal cookie-based authentication
  credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Scalix Web Access is prone to an XML External Entity injection
  and to a Cross Site Scripting vulnerability.");

  script_tag(name:"affected", value:"Scalix Web Access versions 11.4.6.12377, and 12.2.0.14697 are
  vulnerable.");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-11-03 14:30:39 +0100 (Mon, 03 Nov 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_scalix_detect.nasl");
  script_mandatory_keys("scalix/installed");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( vers = get_app_version( cpe:CPE, port:port ) )
{
  if( vers == '11.4.6.12377' || vers == '12.2.0.14697' )
  {
      security_message( port:port );
      exit(0);
  }
}

exit(0);
