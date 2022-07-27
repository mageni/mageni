###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_domino_xss_n_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# IBM Lotus Domino Cross Site Scripting and Buffer Overflow Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:ibm:lotus_domino';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902572");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_bugtraq_id(49701, 49705);
  script_cve_id("CVE-2011-3575", "CVE-2011-3576");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("IBM Lotus Domino Cross Site Scripting and Buffer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code with system-level privileges or steal cookie-based authentication
  credentials and launch other attacks.");
  script_tag(name:"affected", value:"IBM Lotus Domino Versions 8.5.2 and prior.");
  script_tag(name:"insight", value:"- Input passed via the 'PanelIcon' parameter in an
  fmpgPanelHeader ReadForm action to WebAdmin.nsf is not properly sanitised
  before being returned to the user. This can be exploited to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.

  - Stack-based buffer overflow error in the NSFComputeEvaluateExt function
  in Nnotes.dll allows remote authenticated users to execute arbitrary code
  via a long 'tHPRAgentName' parameter in an fmHttpPostRequest OpenForm
  action to WebAdmin.nsf.");
  script_tag(name:"solution", value:"Upgrade to IBM Lotus Domino Versions 8.5.2 FP2, 8.5.3 or later.");
  script_tag(name:"summary", value:"The host is running IBM Lotus Domino Server and is prone to cross
  site scripting and buffer overflow vulnerabilities.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69802");
  script_xref(name:"URL", value:"http://www.research.reversingcode.com/index.php/advisories/73-ibm-ssd-1012211");
  script_xref(name:"URL", value:"http://www.research.reversingcode.com/exploits/IBMLotusDomino_StackOverflowPoC");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/software/lotus/products/domino/");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

if( ! vers = get_highest_app_version( cpe:CPE ) ) exit( 0 );

vers = ereg_replace( pattern:"FP", string:vers, replace:".FP" );

if( version_is_less( version:vers, test_version:"8.5.2.FP2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.5.2 FP2" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
