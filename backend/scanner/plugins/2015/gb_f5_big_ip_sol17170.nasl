###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_sol17170.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# F5 BIG-IP - SOL17170 - Java vulnerability CVE-2015-4736
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105361");
  script_cve_id("CVE-2015-4736");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("F5 BIG-IP - SOL17170 - Java vulnerability CVE-2015-4736");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/17000/100/sol17170.html?sr=48315211");

  script_tag(name:"impact", value:"Confidentiality, integrity, and availability may be affected when exploited by attackers. However, affected F5 products that contain the vulnerable software component do not use them in a way that exposes this vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified vulnerability in Oracle Java SE 7u80 and 8u45 allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Deployment. (CVE-2015-4736)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-18 14:39:37 +0200 (Fri, 18 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_f5_big_ip_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");

  script_tag(name:"deprecated", value:TRUE); # advisory was changed. no f5 product is affected

  exit(0);
}

exit(66);

include("version_func.inc");
include("host_details.inc");

active_modules = get_kb_item( "f5/big_ip/active_modules" );
if( ! active_modules ) exit( 0 );

version = get_app_version( cpe:CPE );
if( ! version ) exit( 0 );

hotfix = "0";

if( hf = get_kb_item( "f5/big_ip/hotfix" ) ) hotfix = hf;

if( "LTM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.6.0" ) )
  {
    LTM_VULN = TRUE;
  }


  if( LTM_VULN )
  {
   affected_modules += "LTM ";
   unaffected += '\tLTM: 11.0.0-11.4.1 10.1.0-10.2.4\n';
  }
}

if( "AAM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.6.0" ) )
  {
    AAM_VULN = TRUE;
  }


  if( AAM_VULN )
  {
   affected_modules += "AAM ";
   unaffected += '\tAAM: 11.4.0-11.4.1\n';
  }
}

if( "AFM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.6.0" ) )
  {
    AFM_VULN = TRUE;
  }


  if( AFM_VULN )
  {
   affected_modules += "AFM ";
   unaffected += '\tAFM: 11.3.0-11.4.1\n';
  }
}

if( "AVR" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.6.0" ) )
  {
    AVR_VULN = TRUE;
  }


  if( AVR_VULN )
  {
   affected_modules += "AVR ";
   unaffected += '\tAVR: 11.0.0-11.4.1\n';
  }
}

if( "APM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.6.0" ) )
  {
    APM_VULN = TRUE;
  }


  if( APM_VULN )
  {
   affected_modules += "APM ";
   unaffected += '\tAPM: 11.0.0-11.4.1 10.1.0-10.2.4\n';
  }
}

if( "ASM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.6.0" ) )
  {
    ASM_VULN = TRUE;
  }


  if( ASM_VULN )
  {
   affected_modules += "ASM ";
   unaffected += '\tASM: 11.0.0-11.4.1 10.1.0-10.2.4\n';
  }
}

if( "GTM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.6.0" ) )
  {
    GTM_VULN = TRUE;
  }


  if( GTM_VULN )
  {
   affected_modules += "GTM ";
   unaffected += '\tGTM: 11.0.0-11.4.1 10.1.0-10.2.4\n';
  }
}

if( "LC" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.6.0" ) )
  {
    LC_VULN = TRUE;
  }


  if( LC_VULN )
  {
   affected_modules += "LC ";
   unaffected += '\tLC: 11.0.0-11.4.1 10.1.0-10.2.4\n';
  }
}

if( "PEM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.6.0" ) )
  {
    PEM_VULN = TRUE;
  }


  if( PEM_VULN )
  {
   affected_modules += "PEM ";
   unaffected += '\tPEM: 11.3.0-11.4.1\n';
  }
}

if( affected_modules )
{
  report = 'Installed Version: ' + version + '\n' +
           'Affected Modules: ' + affected_modules + '\n';

  if( hotfix ) report += 'Installed Hotfix: ' + hotfix + '\n';

  report += '\nUnaffected:\n\n' + unaffected + '\n';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

