###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Silverlight Multiple Memory Leak Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801935");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_cve_id("CVE-2011-1844", "CVE-2011-1845");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Silverlight Multiple Memory Leak Vulnerabilities");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2526954");
  script_xref(name:"URL", value:"http://isc.sans.edu/diary.html?storyid=10747");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_silverlight_detect.nasl");
  script_mandatory_keys("Microsoft/Silverlight/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause denial of service.");
  script_tag(name:"affected", value:"Microsoft Silverlight version 4 before 4.0.60310.0");
  script_tag(name:"insight", value:"The flaws exist due to:

  - An error in handling of 'popup' control and a custom 'DependencyProperty'
    property.

  - An error in the 'DataGrid' control implementation, which allows remote
    attacker to consume memory via an application involving subscriptions to
    an INotifyDataErrorInfo.ErrorsChanged event or TextBlock or a TextBox
    element.");
  script_tag(name:"solution", value:"Upgrade to Microsoft Silverlight 4.0.60310.0 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Microsoft Silverlight and is prone to
  to multiple memory leak vulnerabilities.");
  script_xref(name:"URL", value:"http://www.microsoft.com/getsilverlight/Get-Started/Install/Default.aspx");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( vers !~ "^4\." ) exit( 99 );

if( version_in_range( version:vers, test_version:"4.0", test_version2:"4.0.60309.0" ) ) {
  report = report_fixed_ver( installed_version:vers, vulnerable_range:"4.0 - 4.0.60309.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
