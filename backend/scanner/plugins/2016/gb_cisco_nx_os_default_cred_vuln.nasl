###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_default_cred_vuln.nasl 11607 2018-09-25 13:53:15Z asteins $
#
# Cisco NX-OS Default Credentials Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807524");
  script_cve_id("CVE-2016-1329");
  script_version("$Revision: 11607 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 15:53:15 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-03-15 13:16:16 +0530 (Tue, 15 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco NX-OS Default Credentials Vulnerability");

  script_tag(name:"summary", value:"This host is running Cisco NX-OS Software
  and is prone to default credentials vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a user account that has
  a default and static password. This account is created at installation and
  cannot be changed or deleted without impacting the functionality of the
  system");

  script_tag(name:"impact", value:"Successful exploitation allow an
  an unauthenticated, remote attacker to log in to the device with the
  privileges of the root user with bash shell access.");

  script_tag(name:"affected", value:"Cisco NX-OS 6.0(2)U6(1) through 6.0(2)U6(5)
  on Nexus 3000 devices and 6.0(2)A6(1) through 6.0(2)A6(5) and 6.0(2)A7(1) on
  Nexus 3500 devices.");

  script_tag(name:"solution", value:"Upgrade to Cisco NX-OS 6.0(2)U6(1a) or
  6.0(2)U6(2a) or 6.0(2)U6(3a) or 6.0(2)U6(4a) or 6.0(2)U6(5a) or later for
  Nexus 3000 devices and 6.0(2)A6(1a) or 6.0(2)A6(2a) or 6.0(2)A6(3a) or
  6.0(2)A6(4a) or 6.0(2)A6(5a) or 6.0(2)A7(1a) or later for Nexus 3500 devices.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-n3k");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");
  exit(0);
}

include("version_func.inc");

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if ( ! nx_model = get_kb_item( "cisco_nx_os/model" ) )   exit( 0 );

if ( ! nx_ver   = get_kb_item( "cisco_nx_os/version" ) ) exit( 0 );

if( nx_model !~ "^3[05]" ) exit( 99 );

if( nx_model =~ "^30")
{
  if(nx_ver  == '6.0(2)U6(1)')
  {
    fix = "6.0(2)U6(1a)";
  }
  else if(nx_ver  == '6.0(2)U6(2)')
  {
    fix = "6.0(2)U6(2a)";
  }
  else if(nx_ver  == '6.0(2)U6(3)')
  {
    fix = "6.0(2)U6(3a)";
  }
  else if(nx_ver  == '6.0(2)U6(4)')
  {
    fix = "6.0(2)U6(4a)";
  }
  else if(nx_ver  == '6.0(2)U6(5)')
  {
    fix = "6.0(2)U6(5a)";
  }
}

else if( nx_model =~ "^35")
{
  if(nx_ver  == '6.0(2)A6(1)')
  {
    fix = "6.0(2)A6(1a)";
  }
  else if(nx_ver  == '6.0(2)A6(2)')
  {
    fix = "6.0(2)A6(2a)";
  }
  else if(nx_ver  == '6.0(2)A6(3)')
  {
    fix = "6.0(2)A6(3a)";
  }
  else if(nx_ver  == '6.0(2)A6(4)')
  {
    fix = "6.0(2)A6(4a)";
  }
  else if(nx_ver  == '6.0(2)A6(5)')
  {
    fix = "6.0(2)A6(5a)";
  }
  else if(nx_ver  == '6.0(2)A7(1)')
  {
    fix = "6.0(2)A7(1a)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:nx_ver, fixed_version:fix);
  security_message(data:report);
  exit( 0 );
}
