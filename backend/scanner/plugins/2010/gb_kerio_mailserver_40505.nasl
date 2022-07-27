###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_mailserver_40505.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Multiple Kerio Products Administration Console File Disclosure and Corruption Vulnerability
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

CPE = "cpe:/a:kerio:kerio_mailserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100666");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-03 13:39:07 +0200 (Thu, 03 Jun 2010)");
  script_bugtraq_id(40505);
  script_name("Multiple Kerio Products Administration Console File Disclosure and Corruption Vulnerability");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_kerio_mailserver_detect.nasl");
  script_mandatory_keys("KerioMailServer/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40505");
  script_xref(name:"URL", value:"http://www.kerio.com");
  script_xref(name:"URL", value:"http://www.kerio.com/support/security-advisories#1006");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to gain access to
  files and corrupt data on a vulnerable computer. This may aid in further attacks.");

  script_tag(name:"affected", value:"Kerio MailServer up to and including version 6.7.3 as well as
  Kerio WinRoute Firewall up to and including version 6.7.1 patch2 are affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Multiple Kerio Products are prone to a file disclosure and corruption
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"6.7.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references." );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );