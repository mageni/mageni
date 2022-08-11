###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bigtree_rce_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# BigTree CMS <= 4.2.22 Remote Upload & Code Execution Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:bigtree:bigtree";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112265");
  script_version("$Revision: 14117 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-05-02 13:38:22 +0200 (Wed, 02 May 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2018-10574");
  script_name("BigTree CMS <= 4.2.22 Remote Upload & Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BigTree/Installed");

  script_tag(name:"summary", value:"BigTree CMS is prone to a remote upload and code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"site/index.php/admin/trees/add/ in BigTree 4.2.22 and earlier allows remote attackers
  to upload and execute arbitrary PHP code because the BigTreeStorage class in core/inc/bigtree/apis/storage.php does not prevent uploads of .htaccess files.");

  script_tag(name:"affected", value:"BigTree CMS versions through 4.2.22.");

  script_tag(name:"solution", value:"Change the affected storage.php file to disable .htaccess extensions or apply the referenced commit.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/issues/335");
  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/commit/609bd17728ee1db0487a42d96028d30537528ae8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"4.2.22" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See solution details" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
