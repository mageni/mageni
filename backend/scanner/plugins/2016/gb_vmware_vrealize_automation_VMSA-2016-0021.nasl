###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_automation_VMSA-2016-0021.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# VMSA-2016-0021: VMware vRealize Automation Partial Information Disclosure Vulnerability
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

CPE = 'cpe:/a:vmware:vrealize_automation';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140077");
  script_cve_id("CVE-2016-5334");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12363 $");
  script_name("VMSA-2016-0021: VMware vRealize Automation Partial Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0021.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to 7.2.0 or later");

  script_tag(name:"summary", value:"Partial information disclosure vulnerability in VMware Identity Manager");
  script_tag(name:"insight", value:"VMware Identity Manager contains a vulnerability that may allow for a partial information disclosure. Successful exploitation of the vulnerability may allow read access to files contained in the /SAAS/WEB-INF and /SAAS/META-INF directories remotely.");

  script_tag(name:"affected", value:"vRealize Automation 7.x < 7.2.0 (vRealize Automation 7.x ships with an RPM-based version of VMware Identity Manager)");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-23 10:02:04 +0100 (Wed, 23 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vrealize_automation_web_detect.nasl");
  script_mandatory_keys("vmware/vrealize/automation/version");

 exit(0);

}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^7\." )
{
  if( version_is_less( version:version, test_version:"7.2.0" ) ) fix = '7.2.0';

  if( version =~ "7\.2\.0" )
  {
    if( build = get_kb_item( "vmware/vrealize/automation/build" ) )
      if( build && int( build ) < 4660246 ) fix = '7.2.0.381 Build 4270058';
  }
}

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit(0);
}

exit( 99 );

