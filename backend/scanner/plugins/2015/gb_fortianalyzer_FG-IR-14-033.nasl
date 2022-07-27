###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortianalyzer_FG-IR-14-033.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# FortiOS: FortiAnalyzer Multiple Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/h:fortinet:fortianalyzer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105200");
  script_bugtraq_id(70887);
  script_cve_id("CVE-2014-2334", "CVE-2014-2335", "CVE-2014-2336");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12106 $");

  script_name("FortiOS: FortiAnalyzer Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-14-033");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to
steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to 5.0.7 or above.");

  script_tag(name:"summary", value:"FortiAnalyzer is prone to multiple cross-site-scripting vulnerabilities
because it fails to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"Versions prior to 5.0.7 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-11 11:16:13 +0100 (Wed, 11 Feb 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_fortianalyzer_version.nasl");
  script_mandatory_keys("fortianalyzer/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

version = get_app_version( cpe:CPE );
if( ! version )
  version = get_kb_item("fortianalyzer/version");

if( ! version ) exit( 0 );

fix = "5.0.7";

if( version_is_less( version:version, test_version:fix ) )
{
  model = get_kb_item("fortianalyzer/model");
  if( ! isnull( model ) ) report = 'Model:             ' + model + '\n';
  report += 'Installed Version: ' + version + '\nFixed Version:     ' + fix + '\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

