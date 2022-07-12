###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_global_protection_mult_vuln.nasl 13783 2019-02-20 11:12:24Z cfischer $
#
# Panda Global Protection 17.0.1 Multiple Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113138");
  script_version("2019-04-04T14:50:45+0000");
  script_tag(name:"last_modification", value:"2019-04-04 14:50:45 +0000 (Thu, 04 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-03-20 10:20:20 +0100 (Tue, 20 Mar 2018)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-6321", "CVE-2018-6322");

  script_name("Panda Global Protection 17.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/GlobalProtection/Ver");

  script_tag(name:"summary", value:"Panda Global Protection is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Following vulnerabilities exist:

  Unquoted Windows search path vulnerability in the panda_url_filtering service in Panda Global Protection allows
local users to gain privileges via a malicious artifact.

  Panda Global Protection allows local users to gain privileges or cause a denial of service by impersonating all
the pipes through a use of \.\pipe\PSANMSrvcPpal -- an 'insecurely created named pipe'. Ensures full access to
Everyone users group.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain complete control over
the target system.");

  script_tag(name:"affected", value:"Panda Global Protection through version 17.0.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Mar/25");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Mar/26");

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

exit( 0 );
