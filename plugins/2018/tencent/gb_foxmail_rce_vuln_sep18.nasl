###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxmail_rce_vuln_sep18.nasl 12343 2018-11-14 02:59:57Z ckuersteiner $
#
# Foxmail <= 7.2.9.115 Remote Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113265");
  script_version("$Revision: 12343 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-14 03:59:57 +0100 (Wed, 14 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-07 15:01:31 +0200 (Fri, 07 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11616");

  script_name("Foxmail <= 7.2.9.115 Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_foxmail_detect.nasl");
  script_mandatory_keys("foxmail/detected");

  script_tag(name:"summary", value:"Tencent Foxmail is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An authenticated user visiting a malicious page or open a malicious file
  could allow an attacker to execute code under the context of the current process.
  The flaw exists within the processing of URI handlers and results from a lack
  of proper validation of a user-supplied string before using it to execute a system call.");
  script_tag(name:"affected", value:"Tencent Foxmail through version 7.2.9.115.");
  script_tag(name:"solution", value:"Update to version 7.2.9.116 or above.");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-18-584/");

  exit(0);
}

CPE = "cpe:/a:tencent:foxmail";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "7.2.9.116" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.2.9.116" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
