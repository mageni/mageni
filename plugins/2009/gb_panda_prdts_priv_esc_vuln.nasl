###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_prdts_priv_esc_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Panda Products Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801080");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4215");
  script_name("Panda Products Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37373");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1023121");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3126");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/507811/100/0/threaded");
  script_xref(name:"URL", value:"http://www.pandasecurity.com/homeusers/support/card?id=80164&idIdioma=2");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/Products/Installed");

  script_tag(name:"affected", value:"Panda AntiVirus Pro 2010 version 9.01.00 and prior.

  Panda Internet Security 2010 version 15.01.00 and prior.

  Panda Global Protection 2010 version 3.01.00 and prior.");

  script_tag(name:"insight", value:"This flaw is due to insecure permissions being set on the 'PavFnSvr.exe'
  file (Everyone/Full Control) within the installation directory, which could be
  exploited by malicious users to replace the affected file with a malicious
  binary which will be executed with SYSTEM privileges.");

  script_tag(name:"solution", value:"Apply the security updates from the linked references.");

  script_tag(name:"summary", value:"This host is running panda Products and is prone to Privilege
  Escalation Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker replace the affected binary file
  with a malicious binary which will be executed with SYSTEM privileges.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( version = get_app_version( cpe:"cpe:/a:pandasecurity:panda_av_pro_2010", nofork:TRUE ) ) {
  if( version_in_range( version:version, test_version:"9.0", test_version2:"9.01.00" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"See references" );
    security_message( port:0, data:report );
  }
}

if( version = get_app_version( cpe:"cpe:/a:pandasecurity:panda_internet_security_2010", nofork:TRUE ) ) {
  if( version_in_range( version:version, test_version:"15.0", test_version2:"15.01.00" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"See references" );
    security_message( port:0, data:report );
  }
}

if( version = get_app_version( cpe:"cpe:/a:pandasecurity:panda_global_protection_2010" ) ) {
  if( version_in_range( version:version, test_version:"3.0", test_version2:"3.01.00" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"See references" );
    security_message( port:0, data:report );
  }
}

exit( 0 );