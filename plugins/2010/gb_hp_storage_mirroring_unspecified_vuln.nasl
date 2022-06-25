###############################################################################
# OpenVAS Vulnerability Test
#
# HP StorageWorks Storage Mirroring Unspecified Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:photoshop_cc2017";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801357");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_cve_id("CVE-2010-1962");
  script_bugtraq_id(40539);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("HP StorageWorks Storage Mirroring Unspecified Vulnerability");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_storage_mirroring_detect.nasl");
  script_mandatory_keys("HP/SWSM/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary code
  via unknown vectors.");
  script_tag(name:"affected", value:"HP StorageWorks Storage Mirroring version 5 before 5.2.1.870.0");
  script_tag(name:"insight", value:"The flaw is caused by unspecified errors.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to HP StorageWorks Storage Mirroring version 5.2.1.870.0 or later.");
  script_tag(name:"summary", value:"This host is installed with HP StorageWorks Storage Mirroring and is
  prone to unspecified vulnerability.");
  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=127557820805729&w=2");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1319");
  script_xref(name:"URL", value:"http://securityvulns.com/news/HP/StorageWorks/StorageMirrori.html");
  script_xref(name:"URL", value:"http://h18006.www1.hp.com/products/storage/software/sm/index.html?psn=storage");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"5.0", test_version2:"5.2.1.869" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.1.870.0", install_path:path );
  security_message( port:0, data:report );
}

exit( 99 );