###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_openview_nnm_mult_vuln_may10.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# HP OpenView Network Node Manager Multiple Vulnerabilities - May10
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:hp:openview_network_node_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900243");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_bugtraq_id(40065, 40067);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1550", "CVE-2010-1551", "CVE-2010-1552",
                "CVE-2010-1553", "CVE-2010-1554");
  script_name("HP OpenView Network Node Manager Multiple Vulnerabilities - May10");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_openview_nnm_detect.nasl");
  script_require_ports("Services/www", 7510);
  script_mandatory_keys("HP/OVNNM/installed");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=127360750704351&w=2");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-10-081/");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-10-082/");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-10-083/");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-10-084/");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-10-085/");
  script_xref(name:"URL", value:"http://support.openview.hp.com/selfsolve/patches");

  script_tag(name:"summary", value:"This host is running HP OpenView Network Node Manager and
  is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"The specific flaw exists,

  - in ovet_demandpoll.exe process, which allows remote attackers to execute
    arbitrary code via format string specifiers in the sel parameter.

  - when _OVParseLLA function defined within ov.dll is called from netmon.exe
    (Network Monitor) daemon, which directly copies the value of the 'sel' POST
    variable into a fixed-length without validating the length causing stack
    buffer overflow.

  - within the snmpviewer.exe CGI. The doLoad function in this process calls
    sprintf() with a %s format specifier without sanitizing the user supplied
    data from POST variables (act and app) causing stack-based buffer overflow.

  - within the getnnmdata.exe CGI. If this CGI is requested with an invalid
    MaxAge parameter or invalid iCount POST parameter a sprintf() call is made
    without validating the length before coping in to a fixed-length stack
    buffer causing stack-based buffer overflow.");
  script_tag(name:"affected", value:"HP OpenView Network Node Manager (OV NNM) 7.01, 7.51, and 7.53");
  script_tag(name:"solution", value:"Upgrade to NNM v7.53 and apply the patch from the references.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
get_app_version( cpe:CPE, port:port );
if( ! vers = get_kb_item( "www/"+ port + "/HP/OVNNM/Ver" ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"B.07.01" ) ||
    version_is_equal( version:vers, test_version:"B.07.51" ) ||
    version_is_equal( version:vers, test_version:"B.07.53" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );