###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_global_protection_system_crash_dos_vuln.nasl 12859 2018-12-21 08:39:42Z ckuersteiner $
#
# Panda Global Protection System Crash DoS Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.108315");
  script_version("$Revision: 12859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 09:39:42 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-12-20 12:31:33 +0100 (Wed, 20 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2017-17683", "CVE-2017-17684");

  script_name("Panda Global Protection System Crash DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/GlobalProtection/Ver");

  script_tag(name:"summary", value:"Panda Global Protection through 17.00.01 is vulnerable to multiple vulnerabilities that can cause a system crash.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the system.");

  script_tag(name:"insight", value:"A system crash can be caused through both a 0xb3702c04 or 0xb3702c44 DeviceIoControl request.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the machine, effectively denying access to it.");

  script_tag(name:"affected", value:"Panda Global Protection through version 17.00.01");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/k0keoyo/Driver-Loaded-PoC/tree/master/Panda-Antivirus/Panda_Security_Antivirus_0xb3702c04_");
  script_xref(name:"URL", value:"https://github.com/k0keoyo/Driver-Loaded-PoC/tree/master/Panda-Antivirus/Panda_Security_Antivirus_0xb3702c44");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/a:pandasecurity:panda_global_protection_2010",
                      "cpe:/a:pandasecurity:panda_global_protection_2014" );

if( ! version = get_app_version( cpe: cpe_list ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "17.00.01" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
