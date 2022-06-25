###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortimanager_cve_2016_3195.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# FortiManager Multiple XSS Vulnerabilities
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

CPE = "cpe:/h:fortinet:fortimanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105865");
  script_cve_id("CVE-2016-3195", "CVE-2016-3194", "CVE-2016-3193");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12338 $");

  script_name("FortiManager Multiple XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://fortiguard.com/advisory/fortimanager-and-fortianalyzer-client-side-xss-vulnerability");
  script_xref(name:"URL", value:"http://fortiguard.com/advisory/fortimanager-and-fortianalyzer-xss-vulnerability");
  script_xref(name:"URL", value:"http://fortiguard.com/advisory/fortimanager-and-fortianalyzer-persistent-xss-vulnerability-1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to FortiManager 5.4.0 and above or 5.2.6 and above or 5.0.12 and above");

  script_tag(name:"summary", value:"FortiManager is prone to multiple XSS vulnerabilities.

  - An XSS vulnerablity in FortiManager/FortiAnalyzer could allow privileged guest user accounts and restricted user accounts
  to inject malicious script to the application-side or client-side of the appliance web-application. This potentially enables XSS attacks.

  - A vulnerablity in FortiManager/FortiAnalyzer address added page could allow malicious script being injected in the input field. This potentially enables XSS attacks.

  - A client side XSS vulnerablity in FortiManager/FortiAnalyzer could allow malicious script being injected in the Web-UI. This potentially enables XSS attacks.");

  script_tag(name:"affected", value:"FortiManager: 5.0.0 - 5.0.11, 5.2.0 - 5.2.5, 5.4.0");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-12 12:59:41 +0200 (Fri, 12 Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_fortimanager_version.nasl");
  script_mandatory_keys("fortimanager/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_in_range( version:version, test_version:'5.0.0', test_version2:'5.0.11' ) ) fix = '5.0.12';
if( version_in_range( version:version, test_version:'5.2.0', test_version2:'5.2.5' ) )  fix = '5.2.6';
if( version_in_range( version:version, test_version:'5.4', test_version2:'5.4.0' ) )    fix = '5.4.1';

if( fix )
{
  model = get_kb_item("fortimanager/model");
  if( ! isnull( model ) ) report = 'Model:             ' + model + '\n';
  report += 'Installed Version: ' + version + '\nFixed Version:     ' + fix + '\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

