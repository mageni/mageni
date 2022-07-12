###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_huawei_products_invalid_mem_access_vuln.nasl 12045 2018-10-24 06:51:17Z mmartin $
#
# Huawei Products Invalid Memory Access Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113195");
  script_version("$Revision: 12045 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 08:51:17 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-24 12:32:45 +0200 (Thu, 24 May 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-17314");

  script_name("Huawei Products Invalid Memory Access Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_huawei_switch_detect.nasl");
  script_mandatory_keys("huawei_switch/detected", "huawei_switch/model", "huawei_switch/version");

  script_tag(name:"summary", value:"Multiple Huawei Switches are prone to an invalid memory access vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An unauthenticated attacker can send malformed SCCP messages to the host.
  Due to insufficient input validation of some values in the messages, buffer errors can be caused.");
  script_tag(name:"impact", value:"Successful exploitation could lead to Denial of Service or execution of arbitrary code.");
  script_tag(name:"affected", value:"Following products and firmware versions are affected:

  - DP300: V500R002C00

  - RP200: V600R006C00

  - TE30 / TE60: V100R001C10, V500R002C00, V600R006C00

  - TE40 / TE50: V500R002C00, V600R006C00");
  script_tag(name:"solution", value:"Following device/firmware combinations contain a fix:

  - DP300: V500R002C00SPCb00

  - RP200 / TE30 / TE40 / TE50 / TE60: V600R006C00SPC500");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180425-02-buffer-en");

  exit(0);
}

CPE = "cpe:/a:huawei:switch";

include( "host_details.inc" );
include( "version_func.inc" );
include( "revisions-lib.inc" );

if( ! model = get_kb_item( "huawei_switch/model" ) ) exit( 0 );
if( ! version = get_kb_item( "huawei_switch/version" ) ) exit( 0 );

if( ( model =~ '^RP200' || model =~ '^TE[3456]0' ) && revcomp( a: version, b: "v600r006c00spc500" ) < 0) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V600R006C00SPC500" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ '^DP300' && revcomp( a: version, b: "v500r002c00spcb00" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V500R002C00SPCb00" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
