###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_sol17381.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# F5 BIG-IP - SOL17381 - OpenJDK vulnerability CVE-2014-0428
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
  script_oid("1.3.6.1.4.1.25623.1.0.105399");
  script_cve_id("CVE-2014-0428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("F5 BIG-IP - SOL17381 - OpenJDK vulnerability CVE-2014-0428");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/17000/300/sol17381.html");

  script_tag(name:"impact", value:"The vulnerable OpenJDK CORBA component is included, but is not used in supported configurations. A local attacker with access to modify and execute code related to the vulnerable components may be able to breach confidentiality, integrity, and availability of the BIG-IP host.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified vulnerability in Oracle Java SE 5.0u55, 6u65, and 7u45, Java SE Embedded 7u45 and OpenJDK 7 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to CORBA.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-14 12:11:59 +0200 (Wed, 14 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_f5_big_ip_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");

  script_tag(name:"deprecated", value:TRUE); # advisory was changed. no f5 products affected

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
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.5.3" ) )
  {
    LTM_VULN = TRUE;
  }

  if( version_in_range( version:version, test_version:"11.0.0", test_version2:"11.4.1" ) ) LTM_VULN = FALSE;
  if( version_in_range( version:version, test_version:"10.1.0", test_version2:"10.2.4" ) ) LTM_VULN = FALSE;

  if( LTM_VULN )
  {
   affected_modules += "LTM ";
   unaffected += '\tLTM: 12.0.0  11.6.0  11.0.0-11.4.1  10.1.0-10.2.4 \n';
  }
}

if( "AAM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.5.3" ) )
  {
    AAM_VULN = TRUE;
  }

  if( version_in_range( version:version, test_version:"11.4.0", test_version2:"11.4.1" ) ) AAM_VULN = FALSE;

  if( AAM_VULN )
  {
   affected_modules += "AAM ";
   unaffected += '\tAAM: 12.0.0  11.6.0  11.4.0-11.4.1 \n';
  }
}

if( "AFM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.5.3" ) )
  {
    AFM_VULN = TRUE;
  }

  if( version_in_range( version:version, test_version:"11.3.0", test_version2:"11.4.1" ) ) AFM_VULN = FALSE;

  if( AFM_VULN )
  {
   affected_modules += "AFM ";
   unaffected += '\tAFM: 12.0.0  11.6.0  11.3.0-11.4.1  \n';
  }
}

if( "AVR" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.5.3" ) )
  {
    AVR_VULN = TRUE;
  }

  if( version_in_range( version:version, test_version:"11.0.0", test_version2:"11.4.1" ) ) AVR_VULN = FALSE;

  if( AVR_VULN )
  {
   affected_modules += "AVR ";
   unaffected += '\tAVR: 12.0.0  11.6.0  11.0.0-11.4.1  \n';
  }
}

if( "APM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.5.3" ) )
  {
    APM_VULN = TRUE;
  }

  if( version_in_range( version:version, test_version:"11.0.0", test_version2:"11.4.1" ) ) APM_VULN = FALSE;
  if( version_in_range( version:version, test_version:"10.1.0", test_version2:"10.2.4" ) ) APM_VULN = FALSE;

  if( APM_VULN )
  {
   affected_modules += "APM ";
   unaffected += '\tAPM: 12.0.0  11.6.0  11.0.0-11.4.1  10.1.0-10.2.4  \n';
  }
}

if( "ASM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.5.3" ) )
  {
    ASM_VULN = TRUE;
  }

  if( version_in_range( version:version, test_version:"11.0.0", test_version2:"11.4.1" ) ) ASM_VULN = FALSE;
  if( version_in_range( version:version, test_version:"10.1.0", test_version2:"10.2.4" ) ) ASM_VULN = FALSE;

  if( ASM_VULN )
  {
   affected_modules += "ASM ";
   unaffected += '\tASM: 12.0.0  11.6.0  11.0.0-11.4.1  10.1.0-10.2.4  \n';
  }
}

if( "GTM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.5.3" ) )
  {
    GTM_VULN = TRUE;
  }

  if( version_in_range( version:version, test_version:"11.0.0", test_version2:"11.4.1" ) ) GTM_VULN = FALSE;
  if( version_in_range( version:version, test_version:"10.1.0", test_version2:"10.2.4" ) ) GTM_VULN = FALSE;

  if( GTM_VULN )
  {
   affected_modules += "GTM ";
   unaffected += '\tGTM: 11.6.0  11.0.0-11.4.1  10.1.0-10.2.4 \n';
  }
}

if( "LC" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.5.3" ) )
  {
    LC_VULN = TRUE;
  }

  if( version_in_range( version:version, test_version:"11.0.0", test_version2:"11.4.1" ) ) LC_VULN = FALSE;
  if( version_in_range( version:version, test_version:"10.1.0", test_version2:"10.2.4" ) ) LC_VULN = FALSE;

  if( LC_VULN )
  {
   affected_modules += "LC ";
   unaffected += '\tLC: 12.0.0  11.6.0  11.0.0-11.4.1  10.1.0-10.2.4 \n';
  }
}

if( "PEM" >< active_modules )
{
  if( version_in_range( version:version, test_version:"11.5.0", test_version2:"11.5.3" ) )
  {
    PEM_VULN = TRUE;
  }

  if( version_in_range( version:version, test_version:"11.3.0", test_version2:"11.4.1" ) ) PEM_VULN = FALSE;

  if( PEM_VULN )
  {
   affected_modules += "PEM ";
   unaffected += '\tPEM: 12.0.0  11.6.0  11.3.0-11.4.1 \n';
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

