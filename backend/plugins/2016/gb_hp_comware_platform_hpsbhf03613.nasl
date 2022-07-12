###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_comware_platform_hpsbhf03613.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# HPE Network Products Remote Denial of Service (DoS), Unauthorized Access
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:hp:comware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105798");
  script_cve_id("CVE-2014-8176", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-1793");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12431 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-06 12:05:47 +0200 (Wed, 06 Jul 2016)");
  script_name("HPE Network Products Remote Denial of Service (DoS), Unauthorized Access");

  script_tag(name:"summary", value:"Potential security vulnerabilities in OpenSSL have been addressed with HPE network products including iMC, VCX, Comware 5 and Comware 7. The vulnerabilities could be exploited remotely resulting in Denial of Service (DoS) or unauthorized access.");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"vuldetect", value:"Check the release version");

  script_xref(name:"URL", value:'https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05184351');

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_hp_comware_platform_detect_snmp.nasl");
  script_mandatory_keys("hp/comware_device");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork: TRUE) ) exit( 0 );
if( ! model = get_kb_item( "hp/comware_device/model" ) ) exit( 0 );
if( ! release = get_kb_item( "hp/comware_device/release" ) ) exit( 0 );

if( model =~ '^1950-(24|48)G' )
{
  report_fix = 'R3109P16';
  fix = '3109P16';
}

else if( model =~ '^(A|A-?)95(0|1)(8|5|2)' )
{
  report_fix = 'R1829P01';
  fix = '1829P01';
}

else if( model =~ '^(A-)?MSR9(0|2)' )
{
  report_fix = 'R2514P10';
  fix = '2514P10';
}

else if( model =~ '^MSR93' )
{
  report_fix = 'R2514P10';
  fix = '2514P10';
}

else if( model =~ '^59(0|2)0' )
{
  report_fix = 'R2422P01';
  fix = '2422P01';
}

else if( model =~ '^58(0|2)0' )
{
  report_fix = 'R1809P11';
  fix = '1809P11';
}

else if( model =~ '(A-)?^MSR20-(2|4)' )
{
  report_fix = 'R2514P10';
  fix = '2514P10';
}

else if( model =~ '^(A-)?MSR20-1[0-5]' )
{
  report_fix = 'R2514P10';
  fix = '2514P10';
}

else if( model =~ '^(A|A-)?5500-' && "EI Switch" >< model )
{
  report_fix = 'R2221P19';
  fix = '2221P19';
}

else if( model =~ '^(A|A-)?5500-' && "HI Switch" >< model )
{
  report_fix = 'R5501P17';
  fix = '5501P17';
}

else if( model =~ '^(A-)?MSR20-(2|4)(0|1)' )
{
  report_fix = 'R2514P10';
  fix = '2514P10';
}

else if( model =~ 'MSR20-1[0-5]' )
{
  report_fix = 'R2514P10';
  fix = '2514P10';
}

else if( model =~ '^(A)?58(0|2)0(AF)?-(14|24|48)(G|XG)' )
{
  report_fix = 'R1809P11';
  fix = '1809P11';
}

else if( model =~ '870 ' )
{
  report_fix = 'R2607P46';
  fix = '2607P46';
}

else if( model =~ '^(A-)?MSR50' )
{
  report_fix = 'R2514P10';
  fix = '2514P10';
}

else if( model =~ '^(A)?5500-(24|48)-(4SFP|PoE+|SFP)' && ( "HI Switch" >< model || 'HI TAA-compliant Switch' >< model ) )
{
  report_fix = 'R5501P17';
  fix = '5501P17';
}

else if( model =~ '^(A|HSR)?66(0|1)[0-8]' && "router" >< tolower( model ))
{
  report_fix = 'R3303P23';
  fix = '3303P23';
}

else if( model =~ '^(A|HSR)?680(0|2|4|8)' )
{
  report_fix = 'R7103P05';
  fix = '7103P05';
}

else if( model =~ '^(A)?5120'&& ( "EI Switch" >< model || "EI TAA-compliant Switch" >< model ) )
{
  report_fix = 'R2221P20';
  fix = '2221P20';
}

else if( model =~ 'MSR30(12|64|44|24)' )
{
  report_fix = 'R0305P04';
  fix = '0305P04';
}

else if( model =~ '^FF 5930' )
{
  report_fix = 'R2422P01';
  fix = '2422P01';
}

else if( model =~ 'Firewall (A-)F1000-S-EI' )
{
  report_fix = 'R3734P08';
  fix = '3734P08';
}

else if( model =~ '^(A-)MSR30-1(6|1|0|)' && "VCX" >!< model )
{
  report_fix = 'R2514P10';
  fix = '2514P10';
}

else if( model =~ '^MSR40(0|6|8)0' )
{
  report_fix = 'R0305P04';
  fix = '0305P04';
}

else if( model =~ '^MSR100(2|3)-(4|8)' )
{
  if( version =~ '^7\\.' )
  {
    report_fix = 'R0305P04';
    fix = '0305P04';
  }
  else
  {
    report_fix = 'R2514P10';
    fix = '2514P10';
  }
}

else if( model =~ '^(A|A-)?125(0|1)(0|8|4)' )
{
  report_fix = 'R1829P01';
  fix = '1829P01';
}

else if( model =~ '(A|A-)?105(0|1)(8|4|2)^' || model =~ 'FF 1190(0|8)' )
{
  report_fix = 'R7170';
  fix = '7170';
}

else if( ( model =~ '^12500' || model =~ '^9500' || model =~ '^(7|10)500' || model =~ '^6600' || model =~ '^8800' || model =~ '^5820' )  && ( "firewall" >< tolower( model ) || 'vpn' >< tolower( model )  ) )
{
  report_fix = 'R3181P07';
  fix = '3181P07';
}

else if( model =~ '^129(0|1)[0-8]' )
{
  report_fix = 'R1138P01';
  fix = '1138P01';
}

else if( model =~ '^(FF )?79(0|1)(0|4)' )
{
  report_fix = 'R2138P01';
  fix = '2138P01';
}

else if( model =~ '^(A|A-)?5130-(24|48)-' )
{
  report_fix = 'R3109P16';
  fix = '3109P16';
}

else if( model =~ '^(A|A-)?5700-(48|40|32)' )
{
  report_fix = 'R2422P01';
  fix = '2422P01';
}

else if( model =~ '^75(0|1)(0|2|3|6)' )
{
  if( version =~ '^7\\.' )
  {
    report_fix = 'R7170';
    fix = 'R7170';
  }
  else if( version =~ '^5\\.' )
  {
    report_fix = 'R6710P01';
    fix = '6710P01';
  }
}

if( ! fix ) exit( 0 );

release = ereg_replace( pattern:'^R', string:release, replace:'' );

if( revcomp( a:release, b:fix ) < 0 )
{
  report = report_fixed_ver( installed_version:"R" + release, fixed_version:report_fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
