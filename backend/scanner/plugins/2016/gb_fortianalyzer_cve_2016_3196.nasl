###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortianalyzer_cve_2016_3196.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# FortiAnalyzer Persistent XSS Vulnerability
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

CPE = "cpe:/h:fortinet:fortianalyzer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105815");
  script_cve_id("CVE-2016-3196");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_version("$Revision: 12313 $");

  script_name("FortiAnalyzer Persistent XSS Vulnerability");

  script_xref(name:"URL", value:"https://fortiguard.com/advisory/fortimanager-and-fortianalyzer-persistent-xss-vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to FortiAnalyzer 5.4.0 and above or 5.2.6 and above.");

  script_tag(name:"summary", value:"When a low privileged user uploads images in the report section, the filenames are not properly sanitized.");

  script_tag(name:"affected", value:"FortiAnalyzer: 5.0.0 - 5.0.11, 5.2.0 - 5.2.5");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-19 10:34:06 +0200 (Tue, 19 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_fortianalyzer_version.nasl");
  script_mandatory_keys("fortianalyzer/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

fix = '5.2.6/5.4.0';

if( version_in_range( version:version, test_version:'5.0.0', test_version2:'5.0.11' ) ||
    version_in_range( version:version, test_version:'5.2.0', test_version2:'5.2.5' ) )
{
  model = get_kb_item("fortianalyzer/model");
  if( ! isnull( model ) ) report = 'Model:             ' + model + '\n';
  report += 'Installed Version: ' + version + '\nFixed Version:     ' + fix + '\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

